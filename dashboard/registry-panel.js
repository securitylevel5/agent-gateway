'use strict';

(function () {
  function esc(s) {
    return String(s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function section(title, count, emptyMessage, rowsHtml) {
    const header = '<div class="registry-section-header">' +
      esc(title) + ' (' + count + ')</div>';
    const body = count === 0
      ? '<div class="registry-empty">' + esc(emptyMessage) + '</div>'
      : rowsHtml;
    return '<div class="registry-section">' + header + body + '</div>';
  }

  function permsLine(perms) {
    if (!perms || perms.length === 0) return '<div class="registry-perms">(no permissions)</div>';
    return '<div class="registry-perms">' + esc(perms.join(', ')) + '</div>';
  }

  function humanRow(h) {
    return '<div class="registry-row">' +
      '<span class="registry-id">' + esc(h.id) + '</span>' +
      permsLine(h.permissions) +
      '</div>';
  }

  function agentRow(a) {
    const meta = a.created_by
      ? '<div class="registry-meta">authorized by ' + esc(a.created_by) + '</div>'
      : '';
    return '<div class="registry-row">' +
      '<span class="registry-id">' + esc(a.id) + '</span>' +
      meta +
      permsLine(a.permissions) +
      '</div>';
  }

  function renderRegistryHtml(snapshot, state) {
    state = state || {};
    let out = '';
    if (state.error) {
      out += '<div class="registry-error">' + esc(state.error) + '</div>';
    }
    if (snapshot) {
      out += section('Humans', snapshot.humans.length, 'No humans registered',
        snapshot.humans.map(humanRow).join(''));
      out += section('Agents', snapshot.agents.length, 'No agents running',
        snapshot.agents.map(agentRow).join(''));
    }
    return out;
  }

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = { renderRegistryHtml };
  } else {
    globalThis.renderRegistryHtml = renderRegistryHtml;
  }
})();
