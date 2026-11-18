'use strict';
// ProGuard sonrası CFR çıktısı kalıntıları: values()/valueOf()/$VALUES silinmiş enum'lar gerçek enum sözdizimine çevrilir,
// 'enum' yorumları ve CFR uyarı notları temizlenir.

function mask(s) {
  return s.replace(/"(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*'|\/\/[^\n]*|\/\*[\s\S]*?\*\//g, m => m.replace(/[^\n]/g, ' '));
}

function matchBrace(masked, open) {
  let d = 0;
  for (let i = open; i < masked.length; i++) {
    if (masked[i] === '{') d++;
    else if (masked[i] === '}' && --d === 0) return i;
  }
  return -1;
}

function fixPseudoEnums(text) {
  if (!/extends\s+(?:java\.lang\.)?Enum\b/.test(text)) return { text, n: 0 };
  let n = 0;
  const hdr = /^([ \t]*)((?:public |private |protected |static |final |abstract )*)class (\w+)\s*\n?\s*extends\s+(?:java\.lang\.)?Enum(?:<\s*\3\s*>)?\s*\{/gm;
  let out = text, m;
  for (let guard = 0; guard < 50; guard++) {
    hdr.lastIndex = 0;
    const masked = mask(out);
    m = null;
    let cand;
    while ((cand = hdr.exec(masked))) {
      const body0 = cand.index + cand[0].length - 1;
      const end = matchBrace(masked, body0);
      if (end < 0) continue;
      const body = out.slice(body0 + 1, end);
      if (!new RegExp(`static\\s+(?:final\\s+)?(?:/\\*\\s*enum\\s*\\*/\\s*)?${cand[3]}\\s+\\w+\\s*=\\s*new\\s+${cand[3]}\\(`).test(body)) continue;
      m = { cand, body0, end, body };
      break;
    }
    if (!m) break;
    const name = m.cand[3], ind = m.cand[1];
    const consts = [];
    const constRe = new RegExp(`^[ \\t]*(?:(?:private|public|protected|static|final)\\s+)*(?:/\\*\\s*enum\\s*\\*/\\s*)?${name}\\s+(\\w+)\\s*=\\s*new\\s+${name}\\(([^;]*)\\);[ \\t]*\\n?`, 'gm');
    let rest = m.body.replace(constRe, (all, cname, args) => {
      let a = args.trim();
      a = a.replace(/^"[^"]*"\s*,\s*\d+\s*(?:,\s*)?/, '');       // (isim, sıra, ...) sentetik argümanları
      consts.push(a ? `${cname}(${a})` : cname);
      return '';
    });
    // $VALUES benzeri dizi ataması olan boş static blok
    rest = rest.replace(new RegExp(`\\n?[ \\t]*static\\s*\\{\\s*(?:${name}\\[\\]\\s+\\w+\\s*=\\s*new\\s+${name}\\[\\]\\{[^}]*\\};\\s*)?\\}[ \\t]*\\n?`, 'g'), '\n');
    // CFR uyarı yorumları
    rest = rest.replace(/\n[ \t]*\/\*\s*\n(?:[ \t]*\*[^\n]*\n)*?[ \t]*\*\/\s*\n(?=[ \t]*private\s+\w+\()/g, '\n');
    const mods = m.cand[2].replace(/\b(final|abstract|static)\s*/g, '').trim();
    const head = `${ind}${mods ? mods + ' ' : ''}enum ${name} {\n${ind}    ${consts.join(',\n' + ind + '    ')}${consts.length ? ';' : ';'}\n`;
    out = out.slice(0, m.cand.index) + head + rest.replace(/^\n+/, '') + out.slice(m.end);
    n++;
  }
  return { text: out, n };
}

/* ProGuard'ın yarım bıraktığı sentetik üyeler ve CFR notları */
function cleanArtifacts(text) {
  let t = text
    .replace(/^[ \t]*\/\*\s*\n(?:[ \t]*\*[ \t]*WARNING - (?:Possible parameter corruption|void declaration)[^\n]*\n)+[ \t]*\*\/[ \t]*\n/gm, '')
    .replace(/\/\*\s*enum\s*\*\/\s*/g, '');
  return t;
}

function fixProguard(text) {
  const a = fixPseudoEnums(text);
  return { text: cleanArtifacts(a.text), n: a.n };
}

module.exports = { fixProguard, fixPseudoEnums };
