(function () {
  const summary = {};

  summary.counts = {
    buttons: document.querySelectorAll('button').length,
    inputs: document.querySelectorAll('input').length,
    textareas: document.querySelectorAll('textarea').length,
    forms: document.querySelectorAll('form').length,
    images: document.querySelectorAll('img').length,
    links: document.querySelectorAll('a').length
  };

  const urlRegex = /(https?:\/\/[^\s"'<>]+)|(\/[a-zA-Z0-9_\-\/]+\.(php|asp|aspx|jsp|json|html|api|do|action|endpoint))/gi;
  summary.endpoints = Array.from(document.documentElement.innerHTML.matchAll(urlRegex)).map(m => m[0]);

  const commentNodes = [];
  const treeWalker = document.createTreeWalker(document, NodeFilter.SHOW_COMMENT, null, false);
  while (treeWalker.nextNode()) commentNodes.push(treeWalker.currentNode.data.trim());
  summary.comments = commentNodes;

  const scripts = Array.from(document.querySelectorAll('script[src]')).map(s => s.src);
  const links = Array.from(document.querySelectorAll('link[href]')).map(l => l.href);
  const allAssets = [...scripts, ...links];
  const getLib = (keyword) => allAssets.find(u => u.toLowerCase().includes(keyword)) || '';

  summary.tech = {
    jQuery: typeof window.jQuery !== 'undefined',
    jQueryVersion: typeof jQuery !== 'undefined' ? jQuery.fn.jquery : '',
    jQueryLink: getLib('jquery'),
    Bootstrap: !!getLib('bootstrap'),
    BootstrapLink: getLib('bootstrap'),
    React: !!window.__REACT_DEVTOOLS_GLOBAL_HOOK__,
    ReactLink: getLib('react'),
    NextJS: !!getLib('_next'),
    NextLink: getLib('_next'),
    Vue: !!window.__VUE_DEVTOOLS_GLOBAL_HOOK__,
    VueLink: getLib('vue'),
    Angular: !!window.ng,
    AngularLink: getLib('angular')
  };

  summary.meta = {
    title: document.title,
    charset: document.characterSet,
    favicon: document.querySelector('link[rel*="icon"]')?.href || 'None'
  };

  const patterns = {
    "Stripe Live Token": /sk_live_[0-9a-zA-Z]{24}/g,
    "Slack Webhook": /https:\/\/hooks.slack.com\/services\/T[A-Z0-9]{8}\/B[A-Z0-9]{8}\/[a-zA-Z0-9]{24}/g,
    "Slack API Token": /xox[baprs]-[0-9a-zA-Z]{10,48}/g,
    "AWS Access Key ID": /AKIA[0-9A-Z]{16}/g,
    "AWS Secret Access Key": /aws(.{0,20})?(secret|private)?(.{0,20})?[a-z0-9\/+=]{40}/gi,
    "Google Maps API Key": /AIza[0-9A-Za-z\-_]{35}/g,
    "Firebase API Key": /AIza[0-9A-Za-z\-_]{35}/g,
    "Facebook Access Token": /EAACEdEose0cBA[0-9A-Za-z]+/g,
    "Twitter Bearer Token": /AAAAAAAAAAAAAAAAAAAAA[0-9A-Za-z%]+/g,
    "GitHub Token": /ghp_[0-9a-zA-Z]{36}/g,
    "GitLab Token": /glpat-[0-9a-zA-Z]{20}/g,
    "Dropbox API Token": /sl\.[a-z0-9\-._~+/]+=*/g,
    "Heroku API Key": /heroku[a-z0-9]{32}/g,
    "SendGrid API Key": /SG\.[a-zA-Z0-9._-]{22}\.[a-zA-Z0-9._-]{43}/g,
    "Mailgun API Key": /key-[0-9a-zA-Z]{32}/g,
    "PagerDuty API Token": /PDAPI[a-zA-Z0-9]{16}/g,
    "Bitly Access Token": /[0-9a-z]{7,10}-[0-9a-zA-Z]{34}/g,
    "Spotify Access Token": /BQ[0-9A-Za-z-]{58,}/g,
    "Visual Studio App Center Token": /[0-9a-f]{32}-[0-9a-f]{32}/g,
    "YouTube API Key": /AIza[0-9A-Za-z\-_]{35}/g,
    "Generic Bearer Token": /Bearer\s+[a-zA-Z0-9\-\.=~_]+/g,
    "Generic JWT": /\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9._-]{10,}\.[a-zA-Z0-9._-]{10,}\b/g,
    "NPM Token": /(?<=_authToken=)[0-9a-zA-Z\-]{36,}/g,
    "Azure SAS Token": /sv=201[0-9]-[0-9]{2}-[0-9]{2}&ss=[a-z]+&srt=[a-z]+&sp=[a-z]+&se=[^&]+&st=[^&]+&spr=https?&sig=[a-zA-Z0-9%]+/g
  };

  const findings = {};
  const textContent = document.body.innerText;
  for (const [label, regex] of Object.entries(patterns)) {
    const matches = textContent.match(regex);
    if (matches) {
      findings[label] = [...new Set(matches)];
    }
  }

  const html = `
  <html><head><title>Page Security Summary</title>
  <style>
    body { font-family: sans-serif; padding: 20px; background: #f4f4f4; }
    h1 { color: #2c3e50; }
    pre { background: #fff; padding: 10px; border: 1px solid #ccc; overflow: auto; white-space: pre-wrap; word-break: break-word; }
    .section { margin-bottom: 30px; }
    a { color: #3498db; word-break: break-word; }
  </style>
  </head><body>
    <h1>Page Overview & Security Scan / Résumé de la page et analyse sécurité</h1>

    <div class="section">
      <h2>Element Counts / Nombre d'éléments</h2>
      <ul>
        <li>Buttons: ${summary.counts.buttons}</li>
        <li>Inputs: ${summary.counts.inputs}</li>
        <li>Textareas: ${summary.counts.textareas}</li>
        <li>Forms: ${summary.counts.forms}</li>
        <li>Images: ${summary.counts.images}</li>
        <li>Links: ${summary.counts.links}</li>
      </ul>
    </div>

    <div class="section">
      <h2>URLs / Endpoints</h2>
      <pre>${summary.endpoints.length ? summary.endpoints.join('\n') : 'None found / Aucun trouvé'}</pre>
    </div>

    <div class="section">
      <h2>HTML Comments / Commentaires HTML</h2>
      <pre>${summary.comments.length ? summary.comments.join('\n') : 'None found / Aucun'}</pre>
    </div>

    <div class="section">
      <h2>Detected Technologies / Technologies détectées</h2>
      <ul>
        <li>jQuery: ${summary.tech.jQuery ? `+ v${summary.tech.jQueryVersion} - <a href="${summary.tech.jQueryLink}" target="_blank">${summary.tech.jQueryLink}</a>` : '-'}</li>
        <li>Bootstrap: ${summary.tech.Bootstrap ? `+ - <a href="${summary.tech.BootstrapLink}" target="_blank">${summary.tech.BootstrapLink}</a>` : '-'}</li>
        <li>React: ${summary.tech.React ? `+ - <a href="${summary.tech.ReactLink}" target="_blank">${summary.tech.ReactLink}</a>` : '-'}</li>
        <li>Next.js: ${summary.tech.NextJS ? `+ - <a href="${summary.tech.NextLink}" target="_blank">${summary.tech.NextLink}</a>` : '-'}</li>
        <li>Vue.js: ${summary.tech.Vue ? `+ - <a href="${summary.tech.VueLink}" target="_blank">${summary.tech.VueLink}</a>` : '-'}</li>
        <li>Angular: ${summary.tech.Angular ? `+ - <a href="${summary.tech.AngularLink}" target="_blank">${summary.tech.AngularLink}</a>` : '-'}</li>
      </ul>
    </div>

    <div class="section">
      <h2>Page Info / Infos sur la page</h2>
      <ul>
        <li>Title / Titre: ${summary.meta.title}</li>
        <li>Charset: ${summary.meta.charset}</li>
        <li>Favicon: <a href="${summary.meta.favicon}" target="_blank">${summary.meta.favicon}</a></li>
      </ul>
    </div>

    <div class="section">
      <h2>Sensitive Data Detection / Données sensibles détectées</h2>
      ${Object.keys(findings).length === 0 ? '<p style="color:green">No sensitive data found / Aucune donnée sensible trouvée.</p>' : ''}
      ${Object.entries(findings).map(([label, vals]) => `<h3>${label}</h3><pre>${vals.join('\n')}</pre>`).join('')}
    </div>

  </body></html>`;

  const win = window.open('', '_blank');
  win.document.open();
  win.document.write(html);
  win.document.close();
})();
