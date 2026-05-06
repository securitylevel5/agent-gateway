const assert = require('node:assert');
const { test } = require('node:test');
const { renderRegistryHtml } = require('./registry-panel');

test('renders Humans and Agents sections with counts', () => {
  const html = renderRegistryHtml({
    humans: [{ id: 'alice', permissions: ['docstore.example.com'] }],
    agents: [
      {
        id: 'research-bot',
        created_by: 'alice',
        permissions: ['docstore.example.com'],
      },
    ],
  });

  assert.match(html, /Humans \(1\)/);
  assert.match(html, /Agents \(1\)/);
  assert.match(html, /alice\b/);
  assert.match(html, /research-bot/);
  assert.match(html, /authorized by alice/);
  assert.match(html, /docstore\.example\.com/);
});

test('empty sections render an empty-state line', () => {
  const html = renderRegistryHtml({ humans: [], agents: [] });
  assert.match(html, /Humans \(0\)/);
  assert.match(html, /Agents \(0\)/);
  assert.match(html, /No humans registered/);
  assert.match(html, /No agents running/);
});

test('error state renders an error line', () => {
  const html = renderRegistryHtml(null, { error: 'Registry unavailable' });
  assert.match(html, /Registry unavailable/);
});

test('escapes HTML in IDs and permissions', () => {
  const html = renderRegistryHtml({
    humans: [{ id: '<script>', permissions: ['<img>'] }],
    agents: [],
  });
  assert.ok(!html.includes('<script>'));
  assert.ok(!html.includes('<img>'));
});

test('agent without created_by omits the attribution line', () => {
  const html = renderRegistryHtml({
    humans: [],
    agents: [{ id: 'orphan-bot', permissions: [] }],
  });
  assert.match(html, /orphan-bot/);
  assert.ok(!html.includes('authorized by'));
});
