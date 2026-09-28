/*
 * Core Alibi analyzer: turns an Open5GS + Kamailio IMS + RTPEngine "all.log"
 * (lines prefixed "[YYYY-MM-DD HH:MM:SS] [SOURCE] ...") into per-UE and per-call
 * verdicts on whether the core/IMS or the radio/phone side ended each service.
 *
 * Browser: exposes window.CoreAlibi. Node: `node analyzer.js all.log [ping_*.log ...] [--json out.json]`.
 * Times are wall-clock milliseconds encoded as if UTC (render with getUTC*).
 */
(function (root) {
  'use strict';

  const MON = { Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5, Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11 };
  const OPEN5GS_NF = new Set(['AMF', 'SMF', 'UPF', 'PCF', 'SCP', 'NRF', 'AUSF', 'UDM', 'UDR', 'BSF', 'NSSF', 'SEPP', 'MME', 'SGWC', 'SGWU', 'HSS', 'PCRF']);

  const RADIO_CAUSE = ['unspecified', 'txnrelocoverall-expiry', 'successful-handover', 'release-due-to-ngran-generated-reason',
    'release-due-to-5gc-generated-reason', 'handover-cancelled', 'partial-handover', 'ho-failure-in-target-5GC-ngran-node-or-target-system',
    'ho-target-not-allowed', 'tngrelocoverall-expiry', 'tngrelocprep-expiry', 'cell-not-available', 'unknown-targetID',
    'no-radio-resources-available-in-target-cell', 'unknown-local-UE-NGAP-ID', 'inconsistent-remote-UE-NGAP-ID',
    'handover-desirable-for-radio-reason', 'time-critical-handover', 'resource-optimisation-handover', 'reduce-load-in-serving-cell',
    'user-inactivity', 'radio-connection-with-ue-lost', 'radio-resources-not-available', 'invalid-qos-combination',
    'failure-in-radio-interface-procedure', 'interaction-with-other-procedure', 'unknown-PDU-session-ID', 'unknown-qos-flow-ID',
    'multiple-PDU-session-ID-instances', 'multiple-qos-flow-ID-instances', 'encryption-and-or-integrity-protection-algorithms-not-supported',
    'ng-intra-system-handover-triggered', 'ng-inter-system-handover-triggered', 'xn-handover-triggered', 'not-supported-5QI-value',
    'ue-context-transfer', 'ims-voice-eps-fallback-or-rat-fallback-triggered', 'up-integrity-protection-not-possible',
    'up-confidentiality-protection-not-possible', 'slice-not-supported', 'ue-in-rrc-inactive-state-not-reachable', 'redirection',
    'resources-not-available-for-the-slice', 'ue-max-integrity-protected-data-rate-reason', 'release-due-to-cn-detected-mobility'];
  const CAUSE_GROUP = {
    1: ['radioNetwork', RADIO_CAUSE],
    2: ['transport', ['transport-resource-unavailable', 'unspecified']],
    3: ['nas', ['normal-release', 'authentication-failure', 'deregister', 'unspecified']],
    4: ['protocol', ['transfer-syntax-error', 'abstract-syntax-error-reject', 'abstract-syntax-error-ignore-and-notify',
      'message-not-compatible-with-receiver-state', 'semantic-error', 'abstract-syntax-error-falsely-constructed-message', 'unspecified']],
    5: ['misc', ['control-processing-overload', 'not-enough-user-plane-processing-resources', 'hardware-failure', 'om-intervention',
      'unknown-PLMN-or-SNPN', 'unspecified']]
  };
  function causeText(g, c) {
    const grp = CAUSE_GROUP[g];
    if (!grp) return `cause ${g}/${c}`;
    return `${grp[0]}: ${grp[1][c] || 'cause ' + c}`;
  }

  const IP_RE = /\d{1,3}(?:\.\d{1,3}){3}/;
  const hexIp = (h) => [0, 2, 4, 6].map((i) => parseInt(h.slice(i, i + 2), 16)).join('.');
  const userOf = (uri) => { const m = /^(?:sips?|tel):\+?([^@;>]+)/.exec(uri || ''); return m ? m[1] : null; };
  const isImsi = (u) => !!u && /^\d{14,15}$/.test(u);
  const imsiFromSuci = (s) => { const m = /suci-\d+-(\d{3})-(\d{2,3})-\d+-\d+-\d+-(\d+)/.exec(s); return m ? m[1] + m[2] + m[3] : null; };

  function createAnalyzer(opts) {
    opts = opts || {};
    const S = {
      lines: 0, bytes: 0, start: null, end: null, sources: {}, tzOffsetSec: null,
      dedupe: new Set(), dedupeQ: [], dedupeMax: 60000,
      prefixKey: '', prefixYear: 0, prefixMs: 0,
      pendInit: null, pendRel: null, pendSpoof: null,
      ran: [], core: [], sessions: [], causes: [], qosRejects: [], smCtx: [], trig: [],
      lifecycle: [], pfcp: [], gnb: [], tun: [], eagain: [], spoof: [], errors: new Map(),
      ipMap: [], ipLast: new Map(), msisdnVotes: new Map(), lastImpu: null,
      sip: [], coreSipIPs: new Set(), dialogs: new Map(), imsMarkers: [], imsTcp: [],
      rtp: new Map(), pings: [], badUl: [], pendBad: null, pendNssai: null
    };

    function seen(key) {
      if (S.dedupe.has(key)) return true;
      S.dedupe.add(key); S.dedupeQ.push(key);
      if (S.dedupeQ.length > S.dedupeMax) S.dedupe.delete(S.dedupeQ.shift());
      return false;
    }
    function prefixTime(line) {
      const k = line.slice(1, 20);
      if (k !== S.prefixKey) {
        S.prefixKey = k;
        S.prefixYear = +k.slice(0, 4);
        S.prefixMs = Date.UTC(S.prefixYear, +k.slice(5, 7) - 1, +k.slice(8, 10), +k.slice(11, 13), +k.slice(14, 16), +k.slice(17, 19));
      }
      return S.prefixMs;
    }
    function sysTime(rest) {
      const m = /^([A-Z][a-z]{2}) +(\d+) (\d\d):(\d\d):(\d\d)/.exec(rest);
      if (!m || MON[m[1]] === undefined) return S.prefixMs;
      return Date.UTC(S.prefixYear, MON[m[1]], +m[2], +m[3], +m[4], +m[5]);
    }
    function mapIp(ip, imsi, t, via, dnn) {
      if (!ip || !imsi || ip === '0.0.0.0') return;
      // registrar dumps repeat every contact every few seconds: keep only changes
      const k = ip + '|' + via;
      if (via !== 'smf' && S.ipLast.get(k) === imsi) return;
      S.ipLast.set(k, imsi); S.ipMap.push({ ip, imsi, t, via, dnn });
    }
    function vote(msisdn, imsi, w) {
      let v = S.msisdnVotes.get(msisdn);
      if (!v) { v = new Map(); S.msisdnVotes.set(msisdn, v); }
      v.set(imsi, (v.get(imsi) || 0) + w);
    }
    function addError(comp, level, msg, t) {
      const tpl = msg.replace(/\(\.\.\/[^)]*\)/g, '').replace(/imsi-\d+|suci-[\d-]+/g, '<UE>').replace(IP_RE, '<IP>')
        .replace(/0x[0-9a-f]+/gi, '<X>').replace(/\d+/g, 'N').replace(/\s+/g, ' ').trim().slice(0, 160);
      const key = comp + '|' + tpl;
      let e = S.errors.get(key);
      if (!e) { e = { comp, level, template: tpl, sample: msg.slice(0, 240), count: 0, first: t, last: t }; S.errors.set(key, e); }
      e.count++; e.last = t;
    }

    function onOpen5gs(nf, rest) {
      const m = /(\d\d)\/(\d\d) (\d\d):(\d\d):(\d\d)\.(\d{3}): \[([\w-]+)\] (\w+): (.*)$/.exec(rest);
      if (!m) {
        // hex dump that follows a UPF "Invalid packet" error (FILE and journal copies land on the same offset)
        const hm = nf === 'UPF' && S.pendBad && /(?:^|: )([0-9a-f]{4}): ([0-9a-f]{2,8}(?: [0-9a-f]{2,8}){0,3})/.exec(rest);
        if (hm && S.prefixMs - S.pendBad.t < 5000) S.pendBad.hex[hm[1]] = hm[2].replace(/ /g, '');
        return;
      }
      const payloadKey = nf + '|' + rest.slice(m.index);
      if (seen(payloadKey)) return;
      const t = Date.UTC(S.prefixYear, +m[1] - 1, +m[2], +m[3], +m[4], +m[5], +m[6]);
      const mod = m[7], lvl = m[8];
      const msg = m[9].replace(/\s*\(\.\.\/(?:src|lib)\/[^)]*\)\s*$/, '');
      const body = msg.trim();
      if (lvl === 'ERROR' || lvl === 'FATAL') addError(nf, lvl, body, t);

      // NF lifecycle
      if (/initialize\.\.\.done/.test(body)) S.lifecycle.push({ t, nf, kind: 'start' });
      else if (/SIGTERM received/.test(body)) S.lifecycle.push({ t, nf, kind: 'stop' });
      else if (lvl === 'FATAL' || /Failed to initialize/.test(body)) S.lifecycle.push({ t, nf, kind: 'crash', text: body });

      if (/PFCP (de-)?associated/.test(body)) {
        const pm = /PFCP (de-)?associated \[?([\d.]+)/.exec(body);
        S.pfcp.push({ t, nf, up: !pm[1], peer: pm[2] });
      }

      if (nf === 'AMF') return onAmf(t, mod, lvl, body, msg);
      if (nf === 'SMF') return onSmf(t, lvl, body);
      if (nf === 'UPF') return onUpf(t, lvl, body);
    }

    function onAmf(t, mod, lvl, body, msg) {
      let mm;
      if (body === 'InitialUEMessage') { S.pendInit = { t, imsi: null, kind: null, rlf: false }; return; }
      if (/^UE Context Release \[Action:(\d)\]/.test(body)) {
        S.pendRel = { t, action: +/Action:(\d)/.exec(body)[1] }; return;
      }
      if ((mm = /^SUCI\[(suci-[^\]]+)\]/.exec(body))) {
        const imsi = imsiFromSuci(mm[1]);
        if (S.pendRel && t - S.pendRel.t <= 50) { S.ran.push({ t: S.pendRel.t, imsi, type: 'release', action: S.pendRel.action }); S.pendRel = null; return; }
        if (S.pendInit && t - S.pendInit.t <= 50 && !S.pendInit.imsi) { S.pendInit.imsi = imsi; flushInit(); }
        return;
      }
      if ((mm = /^\[(suci-[^\]]+)\]\s+(?:5G-S_TMSI|Known UE by 5G-S_TMSI)/.exec(body))) {
        if (S.pendInit && t - S.pendInit.t <= 50 && !S.pendInit.imsi) { S.pendInit.imsi = imsiFromSuci(mm[1]); flushInit(); }
        return;
      }
      if ((mm = /^\[(suci-[^\]]+|imsi-\d+)\] Holding NG Context/.exec(body))) {
        const imsi = mm[1].startsWith('imsi') ? mm[1].slice(5) : imsiFromSuci(mm[1]);
        S.ran.push({ t, imsi, type: 'rlf' }); return;
      }
      if ((mm = /^\[(suci-[^\]]+)\] (?:[Kk]nown|Unknown) UE by SUCI/.exec(body))) {
        if (S.pendInit && t - S.pendInit.t <= 50 && !S.pendInit.imsi) { S.pendInit.imsi = imsiFromSuci(mm[1]); flushInit(); }
        return;
      }
      if (mod === 'gmm' && /^(Registration|Service) request$/.test(body)) {
        let last = null; // an RLF line can sit between the reconnect and this line
        for (let i = S.ran.length - 1; i >= Math.max(0, S.ran.length - 4); i--) if (S.ran[i].type === 'reconnect') { last = S.ran[i]; break; }
        if (last && t - last.t <= 50 && !last.kind) last.kind = body.startsWith('Reg') ? 'registration' : 'service';
        else if (S.pendInit && t - S.pendInit.t <= 50) S.pendInit.kind = body.startsWith('Reg') ? 'registration' : 'service';
        return;
      }
      if (/^Cannot find Requested NSSAI/.test(body)) { S.pendNssai = { t, snssai: [] }; return; }
      if ((mm = /^S_NSSAI\[SST:(\d+)(?: SD:0x([0-9a-f]+))?\]/i.exec(body)) && S.pendNssai && t - S.pendNssai.t <= 50) {
        const sn = `SST ${mm[1]}${mm[2] ? ' / SD 0x' + mm[2].padStart(6, '0') : ''}`;
        if (!S.pendNssai.snssai.includes(sn)) S.pendNssai.snssai.push(sn);
        return;
      }
      if ((mm = /^\[imsi-(\d+)\] (?:De-?[Rr]egistration request)/.exec(body))) { S.ran.push({ t, imsi: mm[1], type: 'ue_dereg' }); return; }
      if ((mm = /^\[imsi-(\d+)\] Registration complete/.exec(body))) { S.ran.push({ t, imsi: mm[1], type: 'reg_complete' }); return; }
      if ((mm = /^\[imsi-(\d+):(\d+):(\d+)\]\[/.exec(body))) {
        const st = +mm[3];
        if ([12, 51, 52, 53].includes(st)) S.smCtx.push({ t, imsi: mm[1], psi: +mm[2], state: st });
        if (st === 11 || st === 16) S.smCtx.push({ t, imsi: mm[1], psi: +mm[2], state: st });
        return;
      }
      if ((mm = /^\[imsi-(\d+):(\d+)\] Receive Update SM context\(([A-Z0-9_-]+)\)/.exec(body))) {
        S.smCtx.push({ t, imsi: mm[1], psi: +mm[2], state: mm[3] }); return;
      }
      if ((mm = /^\[imsi-(\d+):(\d+)\] Release SM [Cc]ontext \[state:(\d+)\]/.exec(body))) {
        S.smCtx.push({ t, imsi: mm[1], psi: +mm[2], state: 'REL' + mm[3] }); return;
      }
      if (/No PDUSessionResourceModifyListModRes/.test(body)) { S.qosRejects.push({ t }); return; }
      if ((mm = /^\[imsi-(\d+)\] (Mobile Reachable Timer Expired|Implicit De-registered|Do Network-initiated De-register UE|Paging failed\. Stop)/.exec(body))) {
        S.core.push({ t, imsi: mm[1], type: mm[2].startsWith('Paging') ? 'paging_failed' : mm[2].startsWith('Mobile') ? 'mobile_unreachable' : mm[2].startsWith('Implicit') ? 'implicit_dereg' : 'net_dereg' });
        return;
      }
      if ((mm = /gNB-N2\[([\d.]+)\] connection refused/.exec(body))) { S.gnb.push({ t, type: 'link_lost', ip: mm[1] }); return; }
      if ((mm = /gNB-N2 accepted\[([\d.]+)\]/.exec(body))) { S.gnb.push({ t, type: 'link_up', ip: mm[1] }); return; }
      if (/^NGReset/.test(body)) { S.gnb.push({ t, type: 'ng_reset' }); return; }
      if ((mm = /Number of gNBs is now (\d+)/.exec(body))) { S.gnb.push({ t, type: 'count', n: +mm[1] }); return; }
      if ((mm = /LOCAL \[[^\]]+\] Timezone\[(-?\d+)\]/.exec(body))) { S.tzOffsetSec = +mm[1]; return; }
      if (/reject/i.test(body) && !/Unsuccessful/.test(body)) {
        const im = /imsi-(\d+)/.exec(body), sm = /(suci-[\d-]+)/.exec(body);
        const cm = /(Registration|Service) reject \[(\d+)\]/.exec(body);
        const ns = S.pendNssai && t - S.pendNssai.t <= 50 ? S.pendNssai.snssai : null;
        S.core.push({ t, imsi: im ? im[1] : sm ? imsiFromSuci(sm[1]) : null, type: 'reject', text: body,
          proc: cm ? cm[1] : null, cause: cm ? +cm[2] : null, snssai: ns && ns.length ? ns : null });
      }
    }
    function flushInit() {
      const p = S.pendInit; S.pendInit = null;
      if (p && p.imsi) S.ran.push({ t: p.t, imsi: p.imsi, type: 'reconnect', kind: p.kind });
    }

    function onSmf(t, lvl, body) {
      let mm;
      if ((mm = /Cause\[Group:(\d+) Cause:(\d+)\]/.exec(body))) { S.causes.push({ t, g: +mm[1], c: +mm[2] }); return; }
      if ((mm = /UE SUPI\[imsi-(\d+)\] DNN\[([^\]]+)\] IPv4\[([\d.]*)\]/.exec(body))) {
        S.sessions.push({ t, imsi: mm[1], dnn: mm[2], ip: mm[3], up: true }); mapIp(mm[3], mm[1], t, 'smf', mm[2]); return;
      }
      if ((mm = /Removed Session: UE IMSI:\[imsi-(\d+)\] DNN:\[([^:\]]+):(\d+)\] IPv4:\[([\d.]*)\]/.exec(body))) {
        S.sessions.push({ t, imsi: mm[1], dnn: mm[2], psi: +mm[3], ip: mm[4], up: false }); mapIp(mm[4], mm[1], t, 'smf', mm[2]); return;
      }
      if ((mm = /^\[imsi-(\d+):(\d+)\] Session Release \[PFCP-Delete-Trigger:(\d+)\]/.exec(body))) {
        S.trig.push({ t, imsi: mm[1], psi: +mm[2], trigger: +mm[3] });
      }
    }

    function onUpf(t, lvl, body) {
      let mm;
      if (/ogs_tun_write\(\) failed/.test(body)) { S.tun.push(t); return; }
      if (/ogs_sendto\(\) failed \(11:/.test(body)) { S.eagain.push(t); return; }
      if ((mm = /^Invalid packet \[IP version:(\d+), Packet Length:(\d+)\]/.exec(body))) {
        S.pendBad = { t, ver: +mm[1], len: +mm[2], hex: {} }; S.badUl.push(S.pendBad); return;
      }
      if ((mm = /Source IP-4 Spoofing APN:(\S+)/.exec(body))) { S.pendSpoof = { t, apn: mm[1] }; return; }
      if ((mm = /SRC:([0-9A-F]{8}), UE:([0-9A-F]{8})/.exec(body)) && S.pendSpoof) {
        S.spoof.push({ t: S.pendSpoof.t, apn: S.pendSpoof.apn, src: hexIp(mm[1]), ue: hexIp(mm[2]) }); S.pendSpoof = null;
      }
    }

    function onKamailio(tag, rest) {
      let mm;
      if (tag === 'SCSCF') {
        if (rest.includes('Dialog call-id: ')) {
          const cid = rest.slice(rest.indexOf('Dialog call-id: ') + 16).trim();
          const d = S.dialogs.get(cid);
          if (d) d.last = S.prefixMs; else S.dialogs.set(cid, { first: S.prefixMs, last: S.prefixMs });
          return;
        }
        if (rest.includes('Public Identity ')) {
          mm = /Public Identity (?:tel:|sips?:)\+?(\d+)/.exec(rest); S.lastImpu = mm ? mm[1] : null; return;
        }
        if (rest.includes('Contact #')) {
          mm = /Contact #\d+ - sips?:(\d+)@(\d{1,3}(?:\.\d{1,3}){3})/.exec(rest);
          if (mm) {
            if (isImsi(mm[1])) {
              mapIp(mm[2], mm[1], S.prefixMs, 'ims-contact');
              // the registrar dump interleaves records across processes, so pairings are only votes
              if (S.lastImpu && !isImsi(S.lastImpu)) vote(S.lastImpu, mm[1], 1);
            }
          }
          return;
        }
        if (rest.includes('contact in the new contact list')) {
          mm = /= \[sips?:(\d+)@[^\]]*\] \(sips?:\d+@(\d{1,3}(?:\.\d{1,3}){3})/.exec(rest);
          if (mm && isImsi(mm[1])) mapIp(mm[2], mm[1], S.prefixMs, 'ims-contact');
          return;
        }
      }
      const isReq = rest.includes('CSCF: ');
      const isErr = rest.includes(' ERROR: ') || rest.includes(' CRITICAL: ');
      const isMark = /dlg_ontimeout|dlg_terminate|Sorry no QoS|Connection timed out|failed \(timeout\)/.test(rest);
      if (!isReq && !isErr && !isMark) return;
      if (seen(tag + '|' + rest)) return;
      const t = sysTime(rest);
      if (isReq && (mm = /(PCSCF|SCSCF|ICSCF): ([A-Z]+) (\S+) \((\S+) \(([0-9a-fA-F.:]+?):(\d+)\) to (.+?), (\S+)\)\s*$/.exec(rest))) {
        const [, node, method, ruri, from, srcIp, , to, cid] = mm;
        if (node !== 'PCSCF') { S.coreSipIPs.add(srcIp); return; }
        const rIp = (/@(\d{1,3}(?:\.\d{1,3}){3})/.exec(ruri) || [])[1] || null;
        S.sip.push({ t, method, ruriUser: userOf(ruri), ruriIp: rIp, fromUser: userOf(from), toUser: userOf(to), srcIp, cid });
        if (method === 'REGISTER' && isImsi(userOf(from))) mapIp(srcIp, userOf(from), t, 'register');
        return;
      }
      if ((mm = /Connection timed out \(110\) \(\[([\d.]+)\]:(\d+)/.exec(rest))) S.imsTcp.push({ t, ip: mm[1], port: +mm[2], node: tag });
      if (/dlg_ontimeout|dlg_terminate|Sorry no QoS/.test(rest)) S.imsMarkers.push({ t, node: tag, text: rest.replace(/^.*?(?:NOTICE|INFO|DEBUG|ERROR|WARNING): /, '').slice(0, 200) });
      if (isErr) {
        const em = /(ERROR|CRITICAL): (.*)$/.exec(rest);
        if (em && !/Connection timed out|tcp_read_req|failed \(timeout\)/.test(em[2])) addError(tag, em[1], em[2].replace(/^<[^>]+> /, ''), t);
      }
    }

    function onRtpengine(rest) {
      const mm = /rtpengine\[\d+\]: (\w+): \[([^\]\s]+)(?: port \d+)?\]: (.*)$/.exec(rest);
      if (!mm) {
        const em = /rtpengine\[\d+\]: (ERR|CRIT|ALERT|EMERG): (.*)$/.exec(rest);
        if (em) addError('RTPENGINE', em[1], em[2], sysTime(rest));
        return;
      }
      if (seen('RTP|' + rest)) return;
      const t = sysTime(rest), lvl = mm[1], cid = mm[2], msg = mm[3];
      let c = S.rtp.get(cid);
      if (!c) { c = { created: t, del: null, timeoutClose: null, streams: [], media: [], mos: {}, statsT: null, curTag: null, tagStreams: 0, pendSsrc: null }; S.rtp.set(cid, c); }
      let m;
      if (/^Received command 'delete'/.test(msg)) { if (!c.del) c.del = t; return; }
      if (/^Closing call due to timeout/.test(msg)) { c.timeoutClose = t; return; }
      if (/^Final packet stats:/.test(msg)) { c.statsT = t; return; }
      if ((m = /^--- Tag '([^']*)', created (\d+):(\d\d) ago/.exec(msg))) {
        c.curTag = m[1]; c.tagRtpIdx = 0; c.tagMedia = []; if (c.statsT) c.created = Math.min(c.created, c.statsT - ((+m[2]) * 60 + (+m[3])) * 1000); return;
      }
      if ((m = /^------ Media #(\d+) \((\w+) over/.exec(msg))) { c.tagMedia.push(m[2]); if (!c.media[+m[1] - 1]) c.media[+m[1] - 1] = m[2]; return; }
      if ((m = /^--------- Port\s+(\S+)\s+<>\s+(\S+?)\s*(\(RTCP\))?\s*, SSRC (\w+), (\d+) p, (\d+) b, (\d+) e, (\d+) ts/.exec(msg))) {
        const rip = (IP_RE.exec(m[2]) || [])[0] || null;
        const rtcp = !!m[3];
        if (!rtcp) c.tagRtpIdx = (c.tagRtpIdx || 0) + 1;
        const idx = Math.max(0, (c.tagRtpIdx || 1) - 1);
        const media = c.media[idx] || c.tagMedia[idx] || (idx === 0 ? 'audio' : 'video');
        c.streams.push({ tag: c.curTag, localDisabled: /^0\.0\.0\.0:0$/.test(m[1]), ip: rip, port: +(m[2].split(':')[1] || 0), rtcp, ssrc: m[4], packets: +m[5], bytes: +m[6], errors: +m[7], lastT: (c.statsT || t) - (+m[8]) * 1000, media });
        return;
      }
      if ((m = /^--- SSRC (\w+)/.exec(msg))) { c.pendSsrc = m[1]; return; }
      if ((m = /^------ Average MOS ([\d.]+), lowest MOS ([\d.]+)/.exec(msg)) && c.pendSsrc) { c.mos[c.pendSsrc] = { avg: +m[1], low: +m[2] }; c.pendSsrc = null; }
      if (lvl === 'ERR' || lvl === 'CRIT') addError('RTPENGINE', lvl, msg, t);
    }

    function pushLine(line) {
      S.lines++; S.bytes += line.length + 1;
      if (line.charCodeAt(0) !== 91 || line.charCodeAt(20) !== 93) return;
      const tagEnd = line.indexOf(']', 23);
      if (tagEnd < 0) return;
      let tag = line.slice(23, tagEnd);
      const rest = line.slice(tagEnd + 2);
      const t0 = prefixTime(line);
      if (S.start === null || t0 < S.start) S.start = t0;
      if (S.end === null || t0 > S.end) S.end = t0;
      S.sources[tag] = (S.sources[tag] || 0) + 1;
      if (tag.endsWith('-FILE')) tag = tag.slice(0, -5);
      if (OPEN5GS_NF.has(tag)) return onOpen5gs(tag, rest);
      if (tag === 'PCSCF' || tag === 'SCSCF' || tag === 'ICSCF') return onKamailio(tag, rest);
      if (tag === 'RTPENGINE') return onRtpengine(rest);
      if (/ERROR|Exception|SEVERE/.test(rest)) addError(tag, 'ERROR', rest.replace(/^[A-Z][a-z]{2} +\d+ [\d:]+ \S+ /, ''), sysTime(rest));
    }

    // ping_<ip>.log: lastModifiedEpochMs is the file's mtime (epoch, UTC)
    function addPingFile(name, text, lastModifiedEpochMs) {
      const ipm = /(\d{1,3}(?:\.\d{1,3}){3})/.exec(name || '');
      const replies = []; let lostAfter = 0;
      const lines = (text || '').split(/\r?\n/);
      for (const ln of lines) {
        if (!ln) continue;
        const ok = /bytes from/.test(ln);
        let t = null, m;
        if ((m = /^\[(\d{9,11}(?:\.\d+)?)\]/.exec(ln))) t = { epoch: +m[1] * 1000 };
        else if ((m = /(\d{4})-(\d\d)-(\d\d)[ T](\d\d):(\d\d):(\d\d)/.exec(ln))) t = { wall: Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]) };
        if (ok) replies.push(t); else if (/no answer|Unreachable|timeout|100% packet loss/i.test(ln)) lostAfter++;
      }
      S.pings.push({ ip: ipm ? ipm[1] : name, name, replies: replies.length, firstTs: replies.find((r) => r) || null,
        lastTs: [...replies].reverse().find((r) => r) || null, mtimeEpoch: lastModifiedEpochMs || null, empty: replies.length === 0 });
    }
    function addPingManual(ip, lastReplyWall, note) { S.pings.push({ ip, name: note || 'manual', replies: 1, manualWall: lastReplyWall }); }

    function finish(extra) { return buildResult(S, Object.assign({}, opts, extra || {})); }
    return { pushLine, addPingFile, addPingManual, finish, state: S };
  }

  /* ------------------------------------------------------------------ */
  // A log can span several test runs (gNB restarts, core restarts, days of idle).
  // Runs are cut at NG Reset / N2 loss / N2 setup and at core restarts.
  function detectRuns(S) {
    if (S.start === null) return [];
    const cuts = [];
    for (const g of S.gnb) {
      if (g.type === 'ng_reset' || g.type === 'link_lost') cuts.push({ t: g.t + 5000, why: g.type === 'ng_reset' ? 'gNB reset' : 'gNB link lost' });
      else if (g.type === 'link_up') cuts.push({ t: g.t, why: `gNB ${g.ip} connected` });
    }
    const starts = S.lifecycle.filter((l) => l.kind === 'start' && l.t > S.start + 90000).map((l) => l.t).sort((a, b) => a - b);
    for (let i = 0; i < starts.length; i++) if (!i || starts[i] - starts[i - 1] > 30000) cuts.push({ t: starts[i], why: 'core restart' });
    cuts.sort((a, b) => a.t - b.t);
    const busy = (a, b) => S.ran.some((x) => x.t >= a && x.t < b) || S.sip.some((x) => x.t >= a && x.t < b) || S.sessions.some((x) => x.t >= a && x.t < b);
    const runs = []; let from = S.start, fromWhy = 'log start';
    for (const c of [...cuts, { t: S.end + 1, why: 'log end' }]) {
      const to = Math.min(c.t, S.end);
      if (to - from >= 10 * 60000 && busy(from, to)) runs.push({ from, to, startsWith: fromWhy, endsWith: c.why });
      if (c.t > from) { from = c.t; fromWhy = c.why; }
    }
    return runs;
  }
  function pickWindow(S, runs, opts) {
    if (opts.window === 'all') return null;
    if (opts.window && opts.window.from != null) return { from: opts.window.from, to: opts.window.to };
    if (runs.length < 2) return null;
    const longest = runs.slice().sort((a, b) => (b.to - b.from) - (a.to - a.from))[0];
    return (longest.to - longest.from) >= 0.8 * (S.end - S.start) ? null : { from: longest.from, to: longest.to };
  }
  function windowState(S, w) {
    const inW = (t) => t >= w.from && t <= w.to;
    const f = (arr) => arr.filter((x) => inW(typeof x === 'number' ? x : x.t));
    const W = Object.assign({}, S, { start: Math.max(S.start, w.from), end: Math.min(S.end, w.to) });
    for (const k of ['ran', 'core', 'sessions', 'causes', 'qosRejects', 'smCtx', 'trig', 'lifecycle', 'pfcp', 'gnb', 'tun', 'eagain', 'spoof', 'sip', 'imsMarkers', 'imsTcp', 'badUl']) W[k] = f(S[k]);
    W.rtp = new Map([...S.rtp].filter(([, c]) => inW(c.created) || (c.statsT && inW(c.statsT))));
    W.dialogs = new Map([...S.dialogs].filter(([, d]) => d.last >= w.from && d.first <= w.to));
    return W;
  }
  const GMM_CAUSE = { 3: 'illegal UE', 5: 'PEI not accepted', 6: 'illegal ME', 7: '5GS services not allowed', 9: 'UE identity cannot be derived',
    10: 'implicitly deregistered', 11: 'PLMN not allowed', 12: 'tracking area not allowed', 13: 'roaming not allowed in this area',
    15: 'no suitable cells in tracking area', 22: 'congestion', 27: 'N1 mode not allowed', 62: 'no network slices available',
    65: 'maximum number of PDU sessions reached', 111: 'protocol error' };

  function buildResult(S0, opts) {
    const runs = detectRuns(S0);
    const win = pickWindow(S0, runs, opts);
    const S = win ? windowState(S0, win) : S0;
    const logStart = S.start, logEnd = S.end;
    const tz = S.tzOffsetSec !== null ? S.tzOffsetSec : (opts.tzOffsetSec !== undefined ? opts.tzOffsetSec : 0);
    const wallFromEpoch = (e) => e + tz * 1000;
    const MONS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
    const multiDay = S.end - S.start > 20 * 3600000; // runs longer than a night get dates in the text
    const fmt = (t) => {
      if (t == null) return '—';
      const d = new Date(t);
      return (multiDay ? `${MONS[d.getUTCMonth()]} ${d.getUTCDate()} ` : '') + d.toISOString().slice(11, 19);
    };

    // ---- IP -> IMSI (time-aware) ----
    // SMF session records are authoritative; REGISTER next; S-CSCF contacts last (they can be stale for days)
    const VIAS = ['smf', 'register', 'ims-contact'];
    const ipHist = new Map();
    for (const r of S.ipMap) {
      let h = ipHist.get(r.ip);
      if (!h) { h = { smf: [], register: [], 'ims-contact': [], first: r }; ipHist.set(r.ip, h); }
      h[r.via].push(r); if (r.t < h.first.t) h.first = r;
    }
    for (const h of ipHist.values()) for (const v of VIAS) h[v].sort((a, b) => a.t - b.t);
    function imsiForIp(ip, t) {
      const h = ipHist.get(ip); if (!h) return null;
      const q = t || Infinity;
      for (const via of VIAS) {
        const xs = h[via];
        if (!xs.length || xs[0].t > q) continue;
        let lo = 0, hi = xs.length - 1; // last record at or before q
        while (lo < hi) { const mid = (lo + hi + 1) >> 1; if (xs[mid].t <= q) lo = mid; else hi = mid - 1; }
        return xs[lo].imsi;
      }
      return h.first.imsi;
    }
    // UE IPs = P-CSCF request sources that never appear as S-CSCF/I-CSCF sources
    const ueIPs = new Set();
    for (const r of S.sip) if (!S.coreSipIPs.has(r.srcIp) && r.srcIp !== '127.0.0.1') ueIPs.add(r.srcIp);
    // MSISDN -> IMSI: a request the phone itself sent (its number in From, its session IP as source) outweighs
    // any number of registrar-dump pairings
    const votes = new Map([...S.msisdnVotes].map(([k, v]) => [k, new Map(v)]));
    for (const r of S.sip) {
      if (!ueIPs.has(r.srcIp) || !r.fromUser || isImsi(r.fromUser)) continue;
      const im = imsiForIp(r.srcIp, r.t);
      if (!im) continue;
      let v = votes.get(r.fromUser);
      if (!v) { v = new Map(); votes.set(r.fromUser, v); }
      v.set(im, (v.get(im) || 0) + 1000);
    }
    const msisdnMap = new Map();
    for (const [ms, v] of votes) msisdnMap.set(ms, [...v].sort((a, b) => b[1] - a[1])[0][0]);
    const imsiForUser = (u) => !u ? null : isImsi(u) ? u : (msisdnMap.get(u) || null);

    // ---- UEs ----
    const ues = new Map();
    function ue(imsi) {
      if (!imsi) return null;
      let u = ues.get(imsi);
      if (!u) {
        u = { imsi, msisdn: [], ips: {}, events: [], calls: [], last: {}, findings: [] };
        ues.set(imsi, u);
      }
      return u;
    }
    for (const [ms, im] of msisdnMap) { const u = ue(im); if (!u.msisdn.includes(ms)) u.msisdn.push(ms); }
    const dnnOf = new Map();
    for (const r of S0.ipMap) if (r.dnn) dnnOf.set(r.ip + '|' + r.imsi, r.dnn);
    for (const r of S.ipMap) {
      const u = ue(r.imsi);
      const key = r.dnn || dnnOf.get(r.ip + '|' + r.imsi) || 'ims';
      u.ips[key] = u.ips[key] || [];
      if (!u.ips[key].includes(r.ip)) u.ips[key].push(r.ip);
    }
    const ev = (imsi, e) => { const u = ue(imsi); if (u) u.events.push(e); return u; };

    // ---- causes -> setup failures / releases ----
    const nearestCause = (t) => {
      let best = null;
      for (const c of S.causes) { const d = Math.abs(c.t - t); if (d <= 1500 && (!best || d < best.d)) best = { d, c }; }
      return best ? best.c : null;
    };
    const setupFails = S.smCtx.filter((x) => x.state === 12);
    for (const f of setupFails) {
      const c = nearestCause(f.t);
      ev(f.imsi, { t: f.t, layer: 'ran', kind: 'setup_fail', sev: 'ran', label: 'gNB could not set up the radio bearer',
        detail: `PDU session ${f.psi} resource setup failed${c ? ' — ' + causeText(c.g, c.c) : ''}`, cause: c ? causeText(c.g, c.c) : null });
    }
    for (const q of S.qosRejects) {
      const near = S.smCtx.filter((x) => Math.abs(x.t - q.t) <= 3000).sort((a, b) => Math.abs(a.t - q.t) - Math.abs(b.t - q.t))[0];
      if (near) ev(near.imsi, { t: q.t, layer: 'ran', kind: 'qos_reject', sev: 'ran', label: 'gNB refused voice/video QoS flows', detail: 'PDU Session Resource Modify returned no modified flows (GBR voice/video bearer not admitted)' });
    }
    for (const r of S.ran) {
      if (!r.imsi) continue;
      if (r.type === 'reconnect') ev(r.imsi, { t: r.t, layer: 'ran', kind: 'reconnect', sev: 'info', label: r.kind === 'service' ? 'Reconnected (service request)' : 'Reconnected (registration)', detail: 'InitialUEMessage from the gNB' });
      else if (r.type === 'rlf') ev(r.imsi, { t: r.t, layer: 'ran', kind: 'rlf', sev: 'ran', label: 'Came back on a new radio connection', detail: 'The gNB still held the old UE context: the radio link dropped without the gNB telling the core' });
      else if (r.type === 'release') {
        if (r.action === 1) continue;
        const sf = setupFails.find((f) => f.imsi === r.imsi && r.t - f.t >= 0 && r.t - f.t <= 2000);
        const dr = S.ran.find((x) => x.type === 'ue_dereg' && x.imsi === r.imsi && r.t - x.t >= 0 && r.t - x.t <= 2000);
        const rj = S.core.find((x) => x.type === 'reject' && x.imsi === r.imsi && r.t - x.t >= 0 && r.t - x.t <= 2000);
        if (dr || rj) continue; // the AMF ended the connection after a detach or a reject; not a gNB decision
        const c = sf ? nearestCause(sf.t) : null;
        ev(r.imsi, { t: r.t, layer: 'ran', kind: 'gnb_release', sev: 'ran', label: sf ? 'gNB released the UE after a failed bearer setup' : 'Released to idle by the gNB',
          detail: sf ? (c ? causeText(c.g, c.c) : 'setup failure') : 'UE Context Release (radio connection ended)' });
      }
      else if (r.type === 'ue_dereg') ev(r.imsi, { t: r.t, layer: 'ue', kind: 'ue_dereg', sev: 'ue', label: 'Phone detached itself', detail: 'NAS Deregistration Request from the phone (power-off or airplane mode)' });
    }
    for (const x of S.smCtx) {
      if (x.state === 51) ev(x.imsi, { t: x.t, layer: 'ran', kind: 'gnb_lost', sev: 'ran', label: 'gNB link lost', detail: `Session ${x.psi} deactivated because the gNB's N2 link went down` });
      if (x.state === 52 || x.state === 53) ev(x.imsi, { t: x.t, layer: 'ran', kind: 'gnb_reset', sev: 'ran', label: 'gNB reset', detail: `Session ${x.psi} deactivated by an NG Reset from the gNB` });
    }
    // de-duplicate per-session gNB loss/reset to one per UE per second
    for (const u of ues.values()) {
      const seenKey = new Set();
      u.events = u.events.filter((e) => { if (e.kind !== 'gnb_lost' && e.kind !== 'gnb_reset') return true; const k = e.kind + Math.floor(e.t / 1000); if (seenKey.has(k)) return false; seenKey.add(k); return true; });
    }
    const rejectRuns = new Map(); // imsi|cause|slice -> latest collapsed reject event
    const rejectList = [];        // every collapsed reject event, with its UE
    for (const c of S.core) {
      if (!c.imsi) continue;
      if (c.type === 'reject') {
        const key = `${c.imsi}|${c.cause}|${c.snssai ? c.snssai.join(',') : ''}`;
        const prev = rejectRuns.get(key);
        if (prev && c.t - prev.lastT <= 30 * 60000) { prev.count++; prev.lastT = c.t; continue; }
        const what = c.proc ? `${c.proc.toLowerCase()}` : 'a request';
        const e = { t: c.t, layer: 'core', kind: 'reject', sev: 'core', count: 1, lastT: c.t, cause: c.cause, snssai: c.snssai, proc: c.proc,
          label: `Core refused ${what}${c.cause != null ? ` (5GMM #${c.cause}${GMM_CAUSE[c.cause] ? ' ' + GMM_CAUSE[c.cause] : ''})` : ''}`,
          detail: c.snssai ? `The phone asked for slice ${c.snssai.join(', ')}, which this core does not serve. The phone is still using a slice list from another network.` : c.text || 'reject' };
        rejectRuns.set(key, e); rejectList.push([c.imsi, e]); ev(c.imsi, e); continue;
      }
      const map = { mobile_unreachable: ['Core marked the UE unreachable', 'Mobile reachable timer expired (no contact since the UE went idle)'],
        implicit_dereg: ['Core deregistered the UE (implicit)', 'Implicit deregistration after the UE stayed unreachable'],
        net_dereg: ['Core started network deregistration', 'Network-initiated deregistration'],
        paging_failed: ['Paging failed', 'Downlink data was waiting but the UE did not answer paging'] }[c.type];
      ev(c.imsi, { t: c.t, layer: 'core', kind: c.type, sev: 'info', label: map[0], detail: map[1] });
    }
    for (const [, e] of rejectList) if (e.count > 1) { e.label += ` ×${e.count}`; e.detail += ` Repeated ${e.count} times until ${fmt(e.lastT)}.`; }

    // ---- NF restarts: an operator's systemctl restart (SIGTERM first) vs an unexpected one ----
    const warmup = logStart + 90 * 1000;
    const restarts = [];
    for (const l of S.lifecycle) {
      if (l.kind !== 'start' || l.t <= warmup) continue;
      const planned = S0.lifecycle.some((x) => x.nf === l.nf && x.kind === 'stop' && l.t - x.t >= 0 && l.t - x.t <= 120000);
      let g = restarts.find((r) => r.planned === planned && l.t - r.end <= 30000 && r.t - l.t <= 30000);
      if (!g) { g = { t: l.t, end: l.t, nfs: [], planned, affected: new Set() }; restarts.push(g); }
      if (!g.nfs.includes(l.nf)) g.nfs.push(l.nf);
      g.t = Math.min(g.t, l.t); g.end = Math.max(g.end, l.t);
    }
    const restartAt = (t) => restarts.find((g) => t >= g.t - 10000 && t <= g.end + 10000);

    // ---- sessions & network-initiated releases ----
    const findings = [];
    for (const s of S.sessions) {
      if (s.up) { ev(s.imsi, { t: s.t, layer: 'core', kind: 'session_up', sev: 'info', label: `${s.dnn} session up`, detail: `IP ${s.ip}` }); continue; }
      const near = (arr, pred, win) => arr.find((x) => pred(x) && s.t - x.t >= -win && s.t - x.t <= win);
      let why = null, blame = false;
      const rs = restartAt(s.t);
      if (near(S.smCtx, (x) => x.imsi === s.imsi && x.psi === s.psi && x.state === 'N1-RELEASED', 5000)) why = 'released by the phone';
      else if (near(S.smCtx, (x) => x.imsi === s.imsi && x.psi === s.psi && /^REL3[234]$/.test(x.state), 3000)) why = 'dropped by the phone: it reported the session as gone when it reconnected';
      else if (near(S.smCtx, (x) => x.imsi === s.imsi && x.psi === s.psi && x.state === 'REL31', 3000)
        && near(S.ran, (x) => x.imsi === s.imsi && x.type === 'reconnect' && x.kind === 'registration', 3000)) why = 'cleared because the phone registered again from scratch (it had already dropped this session)';
      else if (near(S.smCtx, (x) => x.imsi === s.imsi && x.psi === s.psi && x.state === 'DUPLICATED_PDU_SESSION_ID', 3000)) why = 'replaced: the phone re-sent the session request';
      else if (near(S.core, (x) => x.imsi === s.imsi && /dereg/.test(x.type), 3000)) why = 'removed during deregistration';
      else if (near(S.ran, (x) => x.imsi === s.imsi && x.type === 'ue_dereg', 3000)) why = 'removed because the phone detached';
      else if (rs) { why = rs.planned ? 'dropped because the core was restarted by an operator' : 'dropped because core NFs restarted'; blame = true; rs.affected.add(s.imsi); }
      else { const tr = near(S.trig, (x) => x.imsi === s.imsi && x.psi === s.psi, 3000); why = tr ? `released by the network (PFCP delete trigger ${tr.trigger})` : 'released by the network'; blame = true; }
      ev(s.imsi, { t: s.t, layer: 'core', kind: blame ? 'session_down_net' : 'session_down', sev: blame ? 'core' : 'info', label: `${s.dnn} session removed`, detail: `${s.ip || ''} — ${why}` });
      if (blame && !rs) findings.push({ t: s.t, sev: 'critical', comp: 'SMF', title: `Network released ${s.dnn} session of ${s.imsi}`, detail: `${why}; IP ${s.ip}`, imsi: [s.imsi] });
    }

    // ---- registration rejects: one finding per UE and cause ----
    for (const [imsi, e] of rejectList) {
      const laterOk = S.ran.some((x) => x.type === 'reg_complete' && x.imsi === imsi && x.t > e.lastT);
      e.laterOk = laterOk;
      findings.push({ t: e.t, end: e.lastT > e.t ? e.lastT : undefined, sev: laterOk ? 'warning' : 'critical', comp: 'AMF', imsi: [imsi],
        title: `AMF refused ${e.proc ? e.proc.toLowerCase() : 'service'} for …${imsi.slice(-3)}${e.cause != null ? ` (5GMM #${e.cause}${GMM_CAUSE[e.cause] ? ' ' + GMM_CAUSE[e.cause] : ''})` : ''}${e.count > 1 ? ` ×${e.count}` : ''}`,
        detail: (e.snssai ? `It asks for slice ${e.snssai.join(', ')}, which is not configured on this core. Add that slice to amf.yaml and the subscriber, or clear the phone's stored slices (reset network settings or re-insert the SIM).` : e.detail)
          + (laterOk ? ' It registered successfully later.' : ' It never registered in this run, so it had no data or IMS service.') });
    }

    // ---- UE death evidence from IMS TCP timeouts ----
    for (const x of S.imsTcp) {
      const im = imsiForIp(x.ip, x.t);
      if (im) ev(im, { t: x.t, layer: 'ims', kind: 'ims_tcp_timeout', sev: 'info', label: 'IMS lost its TCP connection to the phone', detail: `${x.node} got no TCP acknowledgements from ${x.ip}:${x.port}; Linux gives up about 15 minutes after the phone stops answering` });
    }
    for (const x of S.spoof) {
      const im = imsiForIp(x.ue, x.t);
      if (im) ev(im, { t: x.t, layer: 'core', kind: 'spoof', sev: 'warn', label: 'UPF dropped packets from a stale IP', detail: `Phone sent from ${x.src} but its session IP is now ${x.ue} (${x.apn})` });
    }

    // ---- uplink the UPF could not parse: what the gNB put in the GTP-U tunnel ----
    const knownUeIp = (ip, t) => ip && ipHist.has(ip) ? imsiForIp(ip, t) : null;
    let badDl = 0;
    for (const b of S.badUl) {
      const bytes = Object.keys(b.hex).sort().map((k) => b.hex[k]).join('').match(/../g) || [];
      const v4 = bytes.findIndex((x, i) => i < 16 && x === '45');
      let src = null, dst = null, prefix = '';
      if (v4 >= 0 && bytes.length >= v4 + 20) {
        const ip = (o) => bytes.slice(v4 + o, v4 + o + 4).map((x) => parseInt(x, 16)).join('.');
        src = ip(12); dst = ip(16); prefix = bytes.slice(0, v4).join('');
      }
      const dlCopy = dst && knownUeIp(dst, b.t) && !knownUeIp(src, b.t);
      if (dlCopy) badDl++;
      const im = dlCopy ? knownUeIp(dst, b.t) : knownUeIp(src, b.t);
      const detail = `The UPF dropped a ${b.len}-byte uplink packet it could not parse (IP version ${b.ver}). `
        + (dlCopy ? `It was ${prefix ? `a ${prefix.length / 2}-byte header (${prefix}) plus ` : ''}a cut-off copy of a downlink packet ${src} → ${dst}: the gNB put downlink data into this UE's uplink tunnel.`
          : src ? `Inner packet ${src} → ${dst}${prefix ? ` behind a ${prefix.length / 2}-byte header (${prefix})` : ''}.` : 'No hex dump was logged.');
      b.imsi = im; b.detail = detail;
      if (im) ev(im, { t: b.t, layer: 'ran', kind: 'gnb_bad_ul', sev: 'ran', label: 'gNB sent a corrupted uplink packet', detail });
    }

    // ---- core health: lifecycle, PFCP, tun, EAGAIN ----
    const episodes = (arr, gapMs) => {
      const out = []; let cur = null;
      for (const t of arr.slice().sort((a, b) => a - b)) {
        if (cur && t - cur.end <= gapMs) { cur.end = t; cur.count++; } else { cur = { start: t, end: t, count: 1 }; out.push(cur); }
      }
      return out;
    };
    const nfTimeline = {};
    for (const l of S.lifecycle) {
      (nfTimeline[l.nf] = nfTimeline[l.nf] || []).push(l);
      if (l.kind === 'crash') findings.push({ t: l.t, sev: 'critical', comp: l.nf, title: `${l.nf} crashed`, detail: l.text || 'FATAL' });
    }
    for (const g of restarts) {
      const list = g.nfs.join(', ');
      findings.push({ t: g.t, end: g.end > g.t ? g.end : undefined, sev: 'critical', comp: g.nfs.length > 2 ? 'Core' : list,
        affected: g.affected.size ? [...g.affected] : undefined,
        title: g.planned ? `Core restarted by an operator (${g.nfs.length} NF${g.nfs.length === 1 ? '' : 's'})` : `${list} restarted unexpectedly`,
        detail: (g.planned ? `systemd stopped and started ${list} (SIGTERM first, so not a crash).` : `${list} initialised again without being stopped first (crash and auto-restart).`)
          + (g.affected.size ? ` It dropped the PDU sessions of ${[...g.affected].map((i) => '…' + i.slice(-3)).join(', ')}.` : ' Sessions and registrations held in memory were lost.') });
    }
    for (const p of S.pfcp) {
      if (!p.up && p.t > warmup && !S.lifecycle.some((l) => l.kind === 'stop' && Math.abs(l.t - p.t) < 5000)) {
        findings.push({ t: p.t, sev: 'critical', comp: p.nf, title: 'SMF–UPF PFCP association lost', detail: `${p.nf} lost PFCP with ${p.peer}` });
      }
    }
    // Which DNN is the dead tun serving? Tun write failures follow session activations on that DNN within seconds.
    const psiDnn = new Map();
    for (const s of S.sessions) if (!s.up && s.psi) psiDnn.set(s.imsi + ':' + s.psi, s.dnn);
    for (const s of S.sessions) if (s.up) {
      const act = S.smCtx.find((x) => x.imsi === s.imsi && x.state === 11 && x.t >= s.t && x.t - s.t <= 3000);
      if (act && !psiDnn.has(s.imsi + ':' + act.psi)) psiDnn.set(s.imsi + ':' + act.psi, s.dnn);
    }
    const activations = S.smCtx.filter((x) => x.state === 11).map((x) => ({ t: x.t, imsi: x.imsi, dnn: psiDnn.get(x.imsi + ':' + x.psi) || null }));
    const tunEp = episodes(S.tun, 600000);
    for (const e of tunEp) {
      const tally = {};
      for (const t of S.tun) {
        if (t < e.start || t > e.end) continue;
        const a = activations.filter((x) => x.dnn && t - x.t >= 0 && t - x.t <= 3000);
        for (const x of a) tally[x.dnn] = (tally[x.dnn] || 0) + 1;
      }
      const dnn = Object.keys(tally).sort((a, b) => tally[b] - tally[a])[0] || null;
      const affected = [...new Set([...S.sessions.filter((s) => !dnn || s.dnn === dnn).map((s) => s.imsi),
        ...activations.filter((x) => (!dnn || x.dnn === dnn) && x.t >= e.start - 600000 && x.t <= e.end).map((x) => x.imsi)])];
      findings.push({ t: e.start, end: e.end, sev: 'critical', comp: 'UPF', dnn, affected,
        title: `UPF discarded uplink packets${dnn ? ' on the ' + dnn + ' DNN' : ''} (tun interface down)`,
        detail: `${e.count} ogs_tun_write() failures from ${fmt(e.start)} to ${fmt(e.end)}. Packets from the phones never left the UPF${dnn ? ' on the ' + dnn + ' DNN' : ''}, so ${dnn === 'ims' ? 'SIP registration and calls could not work' : 'data could not flow'}. The ${dnn === 'ims' ? 'IMS ' : ''}tun interface (ogstun*) was down or had no address.` });
    }
    const eagEp = episodes(S.eagain, 600000);
    if (S.eagain.length) {
      findings.push({ t: S.eagain[0], end: S.eagain[S.eagain.length - 1], sev: 'warning', comp: 'UPF', title: 'UPF dropped some downlink packets (send buffer full)',
        detail: `${S.eagain.length} GTP-U sends failed with EAGAIN across the run. Short bursts cause packet loss, not disconnections. Raising net.core.wmem_default/wmem_max reduces them.`, count: S.eagain.length });
    }
    if (S.spoof.length) findings.push({ t: S.spoof[0].t, sev: 'warning', comp: 'UPF', title: 'UPF dropped packets sent from stale UE IPs', detail: `${S.spoof.length} packets: the phone kept using an old IP after its session was re-created`, count: S.spoof.length });
    if (S.badUl.length) {
      const who = [...new Set(S.badUl.map((b) => b.imsi).filter(Boolean))].map((i) => '…' + i.slice(-3));
      findings.push({ t: S.badUl[0].t, end: S.badUl[S.badUl.length - 1].t, sev: 'warning', comp: 'gNB', notCore: true, count: S.badUl.length,
        title: `gNB sent ${S.badUl.length} corrupted uplink packet${S.badUl.length === 1 ? '' : 's'} (a gNB fault; the UPF dropped them)`,
        detail: (badDl ? `${badDl} of them were cut-off copies of downlink packets put into the uplink tunnel` : 'The UPF could not parse them as IP')
          + (who.length ? ` (${who.join(', ')})` : '') + '. The core only rejected what it received; the corruption happened in the gNB data path.' });
    }
    for (const m of S.imsMarkers) findings.push({ t: m.t, sev: 'critical', comp: m.node, title: 'IMS tore down a dialog', detail: m.text });

    // ---- calls ----
    const byCid = new Map();
    for (const r of S.sip) { if (!byCid.has(r.cid)) byCid.set(r.cid, []); byCid.get(r.cid).push(r); }
    const calls = [];
    for (const [cid, reqs] of byCid) {
      const inv = reqs.filter((r) => r.method === 'INVITE');
      if (!inv.length) continue;
      const fromUe = reqs.filter((r) => ueIPs.has(r.srcIp));
      const first = fromUe.find((r) => r.method === 'INVITE') || inv[0];
      const callerIp = ueIPs.has(first.srcIp) ? first.srcIp : null;
      let calleeIp = (inv.find((r) => r.ruriIp && ueIPs.has(r.ruriIp) && r.ruriIp !== callerIp) || {}).ruriIp || null;
      if (!calleeIp) calleeIp = (fromUe.find((r) => r.srcIp !== callerIp) || {}).srcIp || null;
      const callerImsi = imsiForUser(first.fromUser) || imsiForIp(callerIp, first.t);
      const calleeImsi = imsiForUser(first.toUser) || imsiForIp(calleeIp, first.t);
      const rtp = S.rtp.get(cid) || null;
      const dlg = S.dialogs.get(cid) || null;
      const byes = fromUe.filter((r) => r.method === 'BYE' || r.method === 'CANCEL');
      const reinv = fromUe.filter((r) => r.method === 'INVITE' && r !== first);
      const updates = fromUe.filter((r) => r.method === 'UPDATE');
      const side = (ip) => {
        if (!rtp || !ip) return null;
        const st = rtp.streams.filter((s) => s.ip === ip && !s.rtcp);
        const a = st.filter((s) => s.media === 'audio'), v = st.filter((s) => s.media === 'video');
        const agg = (xs) => xs.length ? { packets: xs.reduce((n, s) => n + s.packets, 0), lastT: Math.max(...xs.map((s) => s.lastT)), mos: xs.map((s) => rtp.mos[s.ssrc]).filter(Boolean)[0] || null } : null;
        return { audio: agg(a), video: agg(v) };
      };
      const A = side(callerIp), B = side(calleeIp);
      // A re-INVITE (R-URI is the other phone's contact) as the first message: the call was already up when the log began
      const startedBefore = !!(first.ruriIp && ueIPs.has(first.ruriIp));
      const pk = (m) => (m && m.audio ? m.audio.packets : 0) + (m && m.video ? m.video.packets : 0);
      // RTPEngine's final stats are the proof of an answered call. Without them: a BYE, an RTPEngine delete, or a
      // dialog still up at the end of the log (a dialog that merely lived a while may just have been ringing)
      const established = startedBefore || (rtp && rtp.statsT ? pk(A) + pk(B) > 20
        : byes.some((b) => b.method === 'BYE') || !!(rtp && rtp.del) || (!!dlg && dlg.last >= logEnd - 30000 && dlg.last - dlg.first > 20000));
      let end = null, endedBy = 'ongoing', byeFrom = [];
      if (byes.length) {
        end = byes[0].t; byeFrom = byes.filter((b) => b.t - end <= 3000).map((b) => b.srcIp === callerIp ? 'caller' : b.srcIp === calleeIp ? 'callee' : b.srcIp);
        byeFrom = [...new Set(byeFrom)]; endedBy = 'phone';
      } else {
        const cands = [dlg && dlg.last < logEnd - 30000 ? dlg.last : null, rtp && rtp.del, rtp && rtp.timeoutClose].filter(Boolean);
        if (cands.length) { end = Math.min(...cands); endedBy = 'network'; }
      }
      if (!established) {
        if (end) end = Math.min(end, Math.max(first.t, dlg ? dlg.last : first.t));
        endedBy = byes.length ? 'cancelled' : 'unanswered';
      }
      const call = { cid, start: first.t, end, endedBy, byeFrom, established, startedBefore,
        caller: { imsi: callerImsi, ip: callerIp, user: first.fromUser, media: A },
        callee: { imsi: calleeImsi, ip: calleeIp, user: first.toUser, media: B },
        hadVideo: !!((A && A.video && A.video.packets > 50) || (B && B.video && B.video.packets > 50)),
        reinvites: reinv.map((r) => ({ t: r.t, by: r.srcIp === callerIp ? 'caller' : 'callee' })),
        refreshes: updates.length, lastRefresh: updates.length ? updates[updates.length - 1].t : null,
        refreshInterval: updates.length > 2 ? Math.round((updates[updates.length - 1].t - updates[0].t) / (updates.length - 1) / 1000) : null,
        rtpTimeout: rtp && rtp.timeoutClose ? rtp.timeoutClose : null };
      calls.push(call);
    }
    calls.sort((a, b) => a.start - b.start);

    // core faults near a time (global or for given imsis)
    const touches = (f, imsis) => {
      if (!imsis) return true;
      const own = f.imsi || f.affected;
      return !own || own.some((i) => imsis.includes(i));
    };
    function coreFaultsNear(t, winBefore, winAfter, imsis) {
      return findings.filter((f) => f.sev === 'critical' && (f.end ? f.end >= t - winBefore && f.t <= t + winAfter : f.t >= t - winBefore && f.t <= t + winAfter) && touches(f, imsis));
    }
    const ranNear = (imsi, t, before, after) => (ues.get(imsi) ? ues.get(imsi).events : []).filter((e) => (e.sev === 'ran' || e.kind === 'ue_dereg') && e.t >= t - before && e.t <= t + after);

    for (const c of calls) {
      const names = { caller: c.caller, callee: c.callee };
      const nm = (p) => p.user || p.imsi || p.ip || '?';
      const reasons = []; let blame = 'ran', headline = '';
      if (c.caller.imsi) { const u = ue(c.caller.imsi); u.calls.push(c.cid); }
      if (c.callee.imsi) { const u = ue(c.callee.imsi); u.calls.push(c.cid); }
      // video
      if (c.hadVideo && c.end) {
        const vt = [c.caller.media && c.caller.media.video, c.callee.media && c.callee.media.video].filter(Boolean).map((v) => v.lastT);
        const vStop = vt.length ? Math.max(...vt) : null;
        if (vStop && vStop >= c.end - 60000) c.videoReason = 'Video ran until the call ended.';
        if (vStop && vStop < c.end - 60000) {
          const ri = c.reinvites.find((r) => Math.abs(r.t - vStop) <= 6000);
          c.videoStop = vStop; c.videoStopBy = ri ? ri.by : null;
          const who = ri ? nm(names[ri.by]) : null;
          const ranPre = [c.caller.imsi, c.callee.imsi].filter(Boolean).flatMap((im) => ranNear(im, vStop, 180000, 5000).map((e) => `${fmt(e.t)} ${im.slice(-3)}: ${e.label}`));
          const cf = coreFaultsNear(vStop, 120000, 5000, [c.caller.imsi, c.callee.imsi]);
          c.videoReason = (ri ? `Video stopped at ${fmt(vStop)} when ${who} sent a re-INVITE removing it (a phone decision).` : `Video stopped at ${fmt(vStop)}.`)
            + (cf.length ? ` Core fault at the same time: ${cf[0].title}.` : ranPre.length ? ` gNB events just before: ${ranPre.slice(0, 3).join('; ')}.` : ' No core or gNB event before it; phones usually do this when video quality is too poor.');
          c.videoBlame = cf.length ? 'core' : 'ran';
        }
      }
      if (c.startedBefore) reasons.push('This call was already up when the log begins (its first message here is a re-INVITE), so caller and callee may be the other way round.');
      if (!c.established) {
        headline = 'Call did not connect'; blame = 'unknown';
        const dl = S.dialogs.get(c.cid);
        const rang = dl && dl.last - dl.first > 20000 ? Math.round((dl.last - dl.first) / 1000) : 0;
        reasons.push(c.byeFrom.length ? `${c.byeFrom.join(' & ')} cancelled before it connected`
          : rang ? `It rang for about ${rang} s and was never answered; the INVITE then timed out. No media ever flowed.` : 'Not answered: no media ever flowed. The rejection code is not in these logs.');
        if (!c.callee.imsi && c.callee.user) reasons.push(`${c.callee.user} never registered in IMS in this log (wrong number, or that phone was not on the network).`);
        const busy = calls.find((o) => o !== c && o.established && o.start < c.start && (!o.end || o.end > c.start)
          && [o.caller.imsi, o.callee.imsi].includes(c.callee.imsi));
        if (busy) reasons.push(`${nm(c.callee)} was already in another call at that moment.`);
      } else if (c.endedBy === 'ongoing') {
        headline = 'Still up at the end of the log'; blame = 'none';
      } else if (c.endedBy === 'network') {
        const la = [c.caller.media && c.caller.media.audio, c.callee.media && c.callee.media.audio].filter(Boolean).map((a) => a.lastT);
        const lastMedia = la.length ? Math.max(...la) : null;
        if (lastMedia && lastMedia < c.end - 60000) {
          headline = 'IMS cleared a call after both phones had gone silent'; blame = 'ran';
          reasons.push(`No BYE from either phone. Media from both phones had stopped by ${fmt(lastMedia)}; the network removed the dead call at ${fmt(c.end)}.`);
        } else {
          headline = 'The network ended the call'; blame = 'core';
          reasons.push(`Neither phone sent a BYE, yet the dialog/media session was removed at ${fmt(c.end)} while media was still flowing.`);
          if (c.rtpTimeout) reasons.push(`RTPEngine closed the media session on timeout at ${fmt(c.rtpTimeout)}.`);
          findings.push({ t: c.end, sev: 'critical', comp: 'IMS', title: `IMS ended call ${nm(c.caller)} → ${nm(c.callee)}`, detail: reasons.join(' '), imsi: [c.caller.imsi, c.callee.imsi].filter(Boolean) });
        }
      } else {
        const who = c.byeFrom.includes('caller') && c.byeFrom.includes('callee') ? 'both' : c.byeFrom[0];
        const actor = who === 'both' ? 'Both phones' : nm(names[who] || {});
        const other = who === 'caller' ? c.callee : who === 'callee' ? c.caller : null;
        const self = who === 'caller' ? c.caller : who === 'callee' ? c.callee : null;
        const oa = other && other.media && other.media.audio;
        const sa = self && self.media && self.media.audio;
        if (other && oa && sa && oa.lastT < c.end - 8000 && sa.lastT < c.end - 8000) {
          const stopT = Math.max(oa.lastT, sa.lastT);
          headline = `Media stopped in both directions; ${actor} hung up`;
          reasons.push(`Media from both phones stopped reaching the core at ${fmt(stopT)}. ${actor} hung up ${Math.round((c.end - stopT) / 1000)} s later (no incoming media).`);
          c.silentSide = 'both'; c.silentAt = stopT;
        } else if (other && oa && oa.lastT < c.end - 8000) {
          headline = `${nm(other)} went silent; ${actor} hung up`;
          reasons.push(`${nm(other)} stopped sending media at ${fmt(oa.lastT)}. ${actor} hung up ${Math.round((c.end - oa.lastT) / 1000)} s later (no incoming media).`);
          c.silentSide = other.imsi; c.silentAt = oa.lastT;
        } else if (who === 'both') {
          headline = 'Both phones hung up at the same moment';
          reasons.push(`Both phones sent BYE at ${fmt(c.end)} while media was still reaching the core from both. The network did not ask them to.`);
        } else {
          headline = `${actor} hung up while media was flowing`;
          reasons.push(`${actor} sent BYE at ${fmt(c.end)} while audio was still arriving from both phones: a phone-side decision, not the network.`);
        }
        if (c.lastRefresh && c.refreshInterval) {
          const due = c.lastRefresh + c.refreshInterval * 1000;
          if (Math.abs(c.end - due) <= 5000) reasons.push(`It happened at the moment the next session refresh was due (${fmt(due)}); every earlier refresh (${c.refreshes}) succeeded.`);
        }
        const cf = coreFaultsNear(c.silentAt || c.end, 120000, 5000, [c.caller.imsi, c.callee.imsi]);
        if (cf.length) { blame = 'core'; reasons.push(`Core fault at that time: ${cf[0].title} (${fmt(cf[0].t)}).`); }
        else {
          const from = (c.silentAt || c.end) - 180000, to = c.end + 120000;
          const silent = [c.caller, c.callee].find((p) => p.imsi && p.imsi === c.silentSide);
          const ranEv = (im) => (ues.get(im) ? ues.get(im).events : []).filter((e) => (e.sev === 'ran' || e.kind === 'ue_dereg') && e.t >= from && e.t <= to);
          const own = silent ? ranEv(silent.imsi) : [];
          const around = [c.caller.imsi, c.callee.imsi].filter(Boolean).flatMap((im) => ranEv(im).map((e) => `${fmt(e.t)} ${im.slice(-3)}: ${e.label}`));
          if (own.length && own.some((e) => e.kind === 'rlf')) {
            const r1 = own.find((e) => e.kind === 'rlf');
            reasons.push(`${nm(silent)} lost its radio link: at ${fmt(r1.t)} it came back on a new radio connection while the gNB still held the old one (the gNB never told the core it had lost the phone).`);
          } else reasons.push(around.length ? `gNB events around it: ${around.slice(0, 3).join('; ')}.` : 'No core, IMS or gNB event around the drop.');
        }
      }
      // media quality
      for (const p of [c.caller, c.callee]) {
        if (p.media && p.media.audio && c.end && c.established) {
          const dur = Math.max(1, (Math.min(p.media.audio.lastT, c.end) - c.start) / 1000);
          p.media.audio.pps = +(p.media.audio.packets / dur).toFixed(2);
        }
      }
      const lowPps = [c.caller, c.callee].filter((p) => p.media && p.media.audio && p.media.audio.pps !== undefined && p.media.audio.pps < 3);
      if (lowPps.length && c.established) reasons.push(`Very little audio reached the core from ${lowPps.map(nm).join(' and ')} (${lowPps.map((p) => p.media.audio.pps + ' pkt/s').join(', ')}; about 6+ expected even in silence), so the radio link was losing most voice packets.`);
      c.headline = headline; c.blame = blame; c.reasons = reasons;
    }

    // ---- pings -> data reachability per UE ----
    const manualMap = opts.ipMap || {};
    function imsiForPingIp(ip, t) {
      if (manualMap[ip]) return { imsi: manualMap[ip], how: 'set by you' };
      const im = imsiForIp(ip, t);
      if (im) return { imsi: im, how: 'from core logs' };
      const n = +String(ip).split('.').pop();
      const cands = [...ues.keys()].filter((x) => +x.slice(-3) === n);
      if (cands.length === 1) return { imsi: cands[0], how: 'guessed from IP number' };
      return { imsi: null, how: '' };
    }
    const pingInfo = [];
    for (const p of S.pings) {
      let last = null, src = '';
      if (p.manualWall) { last = p.manualWall; src = p.name; }
      else if (p.lastTs) { last = p.lastTs.epoch ? wallFromEpoch(p.lastTs.epoch) : p.lastTs.wall; src = 'last reply timestamp'; }
      else if (p.mtimeEpoch && !p.empty) { last = wallFromEpoch(p.mtimeEpoch); src = 'file modified time'; }
      const m = imsiForPingIp(p.ip, last);
      pingInfo.push({ ip: p.ip, imsi: m.imsi, mappedBy: m.how, last, source: src, empty: !!(p.empty && !p.manualWall), name: p.name });
      if (!m.imsi) continue;
      const u = ue(m.imsi);
      u.ips.internet = u.ips.internet || [];
      if (!u.ips.internet.includes(p.ip)) u.ips.internet.push(p.ip);
      if (last) { u.last.ping = last; u.pingSource = src; u.pingMappedBy = m.how; }
      else if (p.empty && !p.manualWall) u.pingEmpty = true;
    }

    // ---- per-UE last activity & verdicts ----
    for (const u of ues.values()) {
      const ips = new Set(Object.values(u.ips).flat());
      const sip = S.sip.filter((r) => ips.has(r.srcIp) && imsiForIp(r.srcIp, r.t) === u.imsi);
      u.last.sip = sip.length ? sip[sip.length - 1].t : null;
      let rtpLast = null;
      for (const c of calls) for (const p of [c.caller, c.callee]) {
        if (c.established && p.imsi === u.imsi && p.media && p.media.audio && p.media.audio.packets > 0) rtpLast = Math.max(rtpLast || 0, p.media.audio.lastT);
      }
      u.last.media = rtpLast;
      const nas = u.events.filter((e) => ['reconnect', 'gnb_release', 'setup_fail', 'rlf', 'ue_dereg', 'qos_reject'].includes(e.kind));
      u.last.nas = nas.length ? nas[nas.length - 1].t : null;
      u.events.sort((a, b) => a.t - b.t);
      u.first = u.events.length ? u.events[0].t : logStart;
    }

    const gnbEvents = S.gnb.filter((g) => g.type !== 'count');
    const lbl = (e) => e.label.charAt(0).toLowerCase() + e.label.slice(1);
    for (const u of ues.values()) {
      const V = { status: 'ok', blame: 'none', headline: '', reasons: [], dropT: null, dropBasis: '', coreImpact: [] };
      const tcp = u.events.filter((e) => e.kind === 'ims_tcp_timeout');
      const inCall = calls.filter((c) => c.silentAt && (c.silentSide === u.imsi || (c.silentSide === 'both' && (c.caller.imsi === u.imsi || c.callee.imsi === u.imsi))));
      const lastSign = Math.max(u.last.sip || 0, u.last.media || 0, u.last.nas || 0) || null;
      if (u.last.ping) {
        if (u.last.ping < logEnd - 180000) { V.dropT = u.last.ping; V.dropBasis = 'last ping reply'; }
      } else if (inCall.length) {
        const c = inCall[inCall.length - 1];
        const laterActivity = Math.max(u.last.sip || 0, u.last.nas || 0) > c.silentAt + 60000;
        if (!laterActivity) { V.dropT = c.silentAt; V.dropBasis = 'last media packet in its call'; }
      }
      const lastActive = V.dropT || u.last.ping || lastSign || logEnd;
      V.coreImpact = findings.filter((f) => f.sev === 'critical' && touches(f, [u.imsi]) && (f.end || f.t) >= u.first && f.t <= lastActive)
        .map((f) => ({ t: f.t, end: f.end || null, title: f.title, detail: f.detail, named: !!(f.imsi || f.affected) }));

      const refused = u.events.filter((e) => e.kind === 'reject' && !e.laterOk);
      if (!V.dropT && refused.length && !u.events.some((e) => e.kind === 'session_up' && e.t > refused[0].t)) {
        const e = refused[refused.length - 1];
        const n = refused.reduce((k, x) => k + x.count, 0), t0 = refused[0].t, t1 = Math.max(...refused.map((x) => x.lastT));
        V.status = 'impaired'; V.blame = 'core';
        V.headline = e.snssai ? 'Core refused to register it: slice not configured' : 'Core refused to register it';
        V.reasons.push(`The AMF rejected ${n > 1 ? `all ${n} registration attempts (${fmt(t0)}–${fmt(t1)})` : `its registration at ${fmt(t0)}`}${e.cause != null ? ` with 5GMM cause #${e.cause}${GMM_CAUSE[e.cause] ? ' (' + GMM_CAUSE[e.cause] + ')' : ''}` : ''}.`);
        if (e.snssai) V.reasons.push(`The phone asks for slice ${e.snssai.join(', ')}, which this core does not serve; it is still using a slice list from another network. Add the slice to amf.yaml and the subscriber, or clear the phone's stored slices (reset network settings or re-insert the SIM).`);
        V.reasons.push('So it never had data or IMS service in this run. This is a configuration mismatch, not a crash, and it has nothing to do with the gNB.');
        u.verdict = V; continue;
      }
      if (!V.dropT) {
        if (u.pingEmpty && !u.last.ping) { V.status = 'nodata'; V.headline = 'Never answered pings in this run'; V.reasons.push('Its ping log was empty.'); }
        else if (V.coreImpact.length) {
          V.status = 'impaired'; V.blame = 'core'; V.headline = 'Service broken by a core fault';
          for (const f of V.coreImpact.slice(0, 3)) V.reasons.push(`${f.title}${f.end ? ` (${fmt(f.t)}–${fmt(f.end)})` : ` at ${fmt(f.t)}`}. ${f.detail}`);
        } else {
          V.status = 'ok'; V.headline = u.last.ping ? 'Reachable until the end of the log' : 'No drop visible in the core logs';
          V.reasons.push(u.last.ping ? `Last ping reply ${fmt(u.last.ping)}.` : `Last activity ${fmt(lastSign)}. Nothing in the core or IMS logs shows it failing. Add its ping log to check data reachability.`);
          if (!u.last.ping && lastSign && logEnd - lastSign > 3600000) {
            const hold = u.events.find((e) => e.t > lastSign && ['gnb_reset', 'gnb_lost', 'implicit_dereg', 'mobile_unreachable'].includes(e.kind));
            const quiet = Math.round(((hold ? hold.t : logEnd) - lastSign) / 3600000);
            V.reasons.push(`After ${fmt(lastSign)} the core got no signalling from it for about ${quiet} h: no release, no detach, no reconnect. `
              + (hold ? `The gNB kept it "connected" until ${fmt(hold.t)} (${lbl(hold)}).` : 'The gNB kept it "connected" to the end of this run.')
              + ' So if its pings stopped in that time, the cause is on the radio side: the core never lost or released it.');
          }
        }
        u.verdict = V; continue;
      }
      const T = V.dropT;
      V.status = 'dropped';
      const cf = coreFaultsNear(T, 180000, 30000, [u.imsi]);
      const dereg = u.events.find((e) => e.kind === 'ue_dereg' && e.t >= T - 60000 && e.t <= T + 180000);
      const gdown = gnbEvents.find((g) => (g.type === 'link_lost' || g.type === 'ng_reset') && g.t >= T - 60000 && g.t <= T + 90000);
      const rel = u.events.filter((e) => ['gnb_release', 'setup_fail', 'rlf'].includes(e.kind) && e.t >= T - 180000 && e.t <= T + 60000);
      const after = u.events.filter((e) => e.t > T + 60000 && ['reconnect', 'ue_dereg', 'gnb_reset', 'gnb_lost', 'implicit_dereg', 'mobile_unreachable'].includes(e.kind));
      const cameBack = after.find((e) => e.kind === 'reconnect');
      if (cf.length) {
        V.blame = 'core'; V.headline = `Core/IMS fault: ${cf[0].title}`;
        V.reasons.push(`${cf[0].detail}`);
      } else if (dereg) {
        V.blame = 'ue'; V.headline = 'Phone detached itself';
        V.reasons.push(`The phone sent a Deregistration Request at ${fmt(dereg.t)} (switch-off, airplane mode or low battery).`);
      } else if (gdown) {
        V.blame = 'ran'; V.headline = gdown.type === 'ng_reset' ? 'gNB reset' : 'gNB link to the core dropped';
        V.reasons.push(`${gdown.type === 'ng_reset' ? 'The gNB sent an NG Reset' : "The gNB's N2 (SCTP) link went down"} at ${fmt(gdown.t)}.`);
      } else if (rel.length && !cameBack) {
        V.blame = 'ran'; V.headline = 'gNB released the UE and it never came back';
        V.reasons.push(rel.map((e) => `${fmt(e.t)} ${lbl(e)}${e.detail ? ' (' + e.detail + ')' : ''}`).join('; ') + '.');
      } else {
        V.blame = 'ran'; V.headline = 'Phone went silent on the radio side';
        V.reasons.push(`No release from the gNB, no detach from the phone, and no core or IMS fault around ${fmt(T)}.`);
        const holdUntil = after.find((e) => ['gnb_reset', 'gnb_lost', 'reconnect', 'implicit_dereg', 'mobile_unreachable'].includes(e.kind));
        V.reasons.push(holdUntil ? `The core still treated it as attached until ${fmt(holdUntil.t)} (${lbl(holdUntil)}).` : 'The core still treated it as attached until the end of the log.');
        if (rel.length) V.reasons.push(`Radio events shortly before: ${rel.map((e) => `${fmt(e.t)} ${lbl(e)}`).join('; ')}.`);
      }
      for (const c of inCall) V.reasons.push(`In its call, media from it stopped at ${fmt(c.silentAt)}${c.silentSide === 'both' ? ' (both directions)' : ''}.`);
      // A read timeout on an established SIP/TCP connection means the phone stopped answering at the latest ~15 min earlier.
      const imsLoss = tcp.map((e) => ({ e, d: e.t - 930000 })).find((x) => (u.last.media && Math.abs(x.d - u.last.media) <= 300000) || (x.d >= T - 300000 && x.d <= T + 1800000));
      if (imsLoss && u.last.ping && imsLoss.d < T - 300000) V.reasons.push(`Its IMS path (SIP and media) died around ${fmt(Math.min(imsLoss.d, u.last.media || imsLoss.d))}, while data pings kept working until ${fmt(u.last.ping)}. IMS confirmed it: TCP to the phone timed out at ${fmt(imsLoss.e.t)}.`);
      else if (imsLoss) V.reasons.push(`IMS also lost contact with it: TCP to the phone timed out at ${fmt(imsLoss.e.t)}.`);
      const cleanup = u.events.filter((e) => e.t > T && ['mobile_unreachable', 'implicit_dereg', 'paging_failed'].includes(e.kind));
      if (cleanup.length) V.reasons.push(`Later core cleanup (a consequence, not the cause): ${cleanup.map((e) => `${fmt(e.t)} ${lbl(e)}`).join('; ')}.`);
      if (V.blame !== 'core' && V.coreImpact.length) V.reasons.push(`Earlier in the night it was hit by a core fault: ${V.coreImpact[0].title}.`);
      u.verdict = V;
    }

    // ---- global ----
    const coreCrit = findings.filter((f) => f.sev === 'critical');
    const ueList = [...ues.values()].filter((u) => u.events.length || u.calls.length || u.last.ping || u.pingEmpty)
      .sort((a, b) => (a.imsi > b.imsi ? 1 : -1));
    const drops = ueList.filter((u) => u.verdict && u.verdict.status === 'dropped');
    const summary = {
      ues: ueList.length, drops: drops.length,
      coreBlamed: ueList.filter((u) => u.verdict && u.verdict.blame === 'core').length + calls.filter((c) => c.blame === 'core').length,
      impaired: ueList.filter((u) => u.verdict && u.verdict.status === 'impaired').length,
      ueDrops: { core: drops.filter((u) => u.verdict.blame === 'core').length, ran: drops.filter((u) => u.verdict.blame === 'ran').length, ue: drops.filter((u) => u.verdict.blame === 'ue').length },
      calls: calls.length, callsEstablished: calls.filter((c) => c.established).length,
      callsCore: calls.filter((c) => c.blame === 'core').length, callsVideoDropped: calls.filter((c) => c.videoStop).length,
      coreFaults: coreCrit.length, coreWarnings: findings.filter((f) => f.sev === 'warning' && !f.notCore).length
    };
    const hourly = (arr) => { const m = new Map(); for (const t of arr) { const h = Math.floor(t / 3600000) * 3600000; m.set(h, (m.get(h) || 0) + 1); } return [...m.entries()].sort((a, b) => a[0] - b[0]).map(([t, n]) => ({ t, n })); };
    const nfNames = [...new Set(Object.keys(S.sources).map((s) => s.replace(/-FILE$/, '')))].sort();
    const errors = [...S.errors.values()].sort((a, b) => b.count - a.count);
    const health = nfNames.map((nf) => {
      const lc = (nfTimeline[nf] || []);
      const errs = errors.filter((e) => e.comp === nf);
      return { nf, lines: (S.sources[nf] || 0) + (S.sources[nf + '-FILE'] || 0), starts: lc.filter((l) => l.kind === 'start').length,
        restartsMidRun: lc.filter((l) => l.kind === 'start' && l.t > warmup).length, crashes: lc.filter((l) => l.kind === 'crash').length,
        stops: lc.filter((l) => l.kind === 'stop').length, errors: errs.reduce((n, e) => n + e.count, 0), topErrors: errs.slice(0, 4) };
    });
    findings.sort((a, b) => a.t - b.t);
    return {
      meta: { lines: S.lines, bytes: S.bytes, start: logStart, end: logEnd, tzOffsetSec: tz, sources: S.sources,
        logStart: S0.start, logEnd: S0.end, window: win, runs },
      summary, findings, calls, pings: pingInfo,
      ues: ueList.map((u) => ({ imsi: u.imsi, msisdn: u.msisdn,
        ips: Object.fromEntries(Object.entries(u.ips).map(([k, v]) => [k, { latest: v.slice(-3), count: v.length }])),
        last: u.last, pingSource: u.pingSource || null, pingMappedBy: u.pingMappedBy || null, verdict: u.verdict, calls: u.calls, events: u.events })),
      gnb: gnbEvents, health, errors: errors.slice(0, 40),
      series: { eagainHourly: hourly(S.eagain), tunHourly: hourly(S.tun) },
      pfcp: S.pfcp, lifecycle: S.lifecycle
    };
  }

  // ---- streaming helper for browsers: File/Blob -> analyzer ----
  async function analyzeBlob(analyzer, blob, onProgress) {
    let stream = blob.stream();
    if (/\.gz$/i.test(blob.name || '') && typeof DecompressionStream !== 'undefined') stream = stream.pipeThrough(new DecompressionStream('gzip'));
    const reader = stream.pipeThrough(new TextDecoderStream()).getReader();
    let buf = '', done = 0, lastTick = 0;
    for (;;) {
      const { value, done: fin } = await reader.read();
      if (fin) break;
      buf += value; done += value.length;
      let i, s = 0;
      while ((i = buf.indexOf('\n', s)) >= 0) { const e = buf.charCodeAt(i - 1) === 13 ? i - 1 : i; analyzer.pushLine(buf.slice(s, e)); s = i + 1; }
      buf = buf.slice(s);
      if (onProgress && done - lastTick > 4e6) { lastTick = done; onProgress(done); await new Promise((r) => setTimeout(r, 0)); }
    }
    if (buf) analyzer.pushLine(buf);
  }

  const api = { createAnalyzer, analyzeBlob, causeText };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.CoreAlibi = api;

  // ---- Node CLI ----
  if (typeof require !== 'undefined' && typeof module !== 'undefined' && require.main === module) {
    const fs = require('fs'), readline = require('readline');
    const args = process.argv.slice(2);
    const jsonOut = args.includes('--json') ? args[args.indexOf('--json') + 1] : null;
    const runArg = args.includes('--run') ? args[args.indexOf('--run') + 1] : null;
    const files = args.filter((a, i) => !a.startsWith('--') && !['--json', '--ping', '--run'].includes(args[i - 1]));
    const manual = args.map((a, i) => (args[i - 1] === '--ping' ? a : null)).filter(Boolean);
    if (!files.length) { console.error('usage: node analyzer.js all.log [ping_<ip>.log ...] [--ping IP=YYYY-MM-DDTHH:MM:SS] [--run N|all] [--json out.json]'); process.exit(1); }
    (async () => {
      const an = createAnalyzer();
      for (const f of files) {
        if (/ping/i.test(require('path').basename(f))) { an.addPingFile(require('path').basename(f), fs.readFileSync(f, 'utf8'), fs.statSync(f).mtimeMs); continue; }
        const rl = readline.createInterface({ input: fs.createReadStream(f), crlfDelay: Infinity });
        for await (const line of rl) an.pushLine(line);
      }
      for (const m of manual) { const [ip, ts] = m.split('='); an.addPingManual(ip, Date.parse(ts + 'Z'), 'ping (given)'); }
      let r = an.finish();
      if (runArg === 'all') r = an.finish({ window: 'all' });
      else if (runArg != null) { const x = r.meta.runs[+runArg - 1]; if (!x) { console.error(`no run ${runArg}`); process.exit(1); } r = an.finish({ window: { from: x.from, to: x.to } }); }
      if (jsonOut) fs.writeFileSync(jsonOut, JSON.stringify(r));
      const f = (t) => (t == null ? '—' : new Date(t).toISOString().replace('T', ' ').slice(0, 19));
      console.log(`Log ${f(r.meta.logStart)} → ${f(r.meta.logEnd)}  (${r.meta.lines} lines)`);
      if (r.meta.runs.length > 1) {
        r.meta.runs.forEach((x, i) => console.log(`  run ${i + 1}: ${f(x.from)} → ${f(x.to)}  (${x.startsWith} … ${x.endsWith})`));
        console.log(r.meta.window ? `Showing ${f(r.meta.start)} → ${f(r.meta.end)}; use --run N or --run all to change.` : 'Showing the whole log.');
      }
      console.log(`UEs ${r.summary.ues}, drops ${r.summary.drops}, calls ${r.summary.calls}, core faults ${r.summary.coreFaults}, warnings ${r.summary.coreWarnings}`);
      for (const x of r.findings) console.log(`  [${x.sev}] ${f(x.t)} ${x.comp}: ${x.title}`);
      for (const u of r.ues) console.log(`\n${u.imsi} ${u.msisdn.join(',')} ${Object.entries(u.ips).map(([k, v]) => k + ':' + v.latest.join('/') + (v.count > 3 ? ' (+' + (v.count - 3) + ')' : '')).join(' ')} ${u.pingMappedBy ? '[ping ' + u.pingMappedBy + ']' : ''}\n  ${u.verdict.status}/${u.verdict.blame} @ ${f(u.verdict.dropT)}: ${u.verdict.headline}\n  - ${u.verdict.reasons.join('\n  - ')}`);
      for (const c of r.calls) console.log(`\nCALL ${f(c.start)} ${c.caller.user}(${(c.caller.imsi || '').slice(-3)}) → ${c.callee.user}(${(c.callee.imsi || '').slice(-3)}) end ${f(c.end)} [${c.blame}] ${c.headline}\n  video: ${c.videoReason || '-'}\n  - ${c.reasons.join('\n  - ')}`);
    })();
  }
})(typeof window !== 'undefined' ? window : globalThis);
