import test from 'node:test';
import assert from 'node:assert/strict';
import { buildLists } from './sync-blocklist.mjs';

const fixture = () => ({
  items: [{type:'ip',value:'203.0.113.1',category:'unclassified'}, {type:'subnet',value:'198.51.100.0/24',category:'abuse'}],
  derivedItems: [{type:'ip',value:'203.0.113.1',category:'abuse'}, {type:'ip',value:'203.0.113.2',category:'restricted'}],
  serverRules: [{type:'server_address',value:'203.0.113.3:27015',category:'abuse'}, {type:'server_address',value:'203.0.113.4:27015',category:'restricted'}],
});
test('exports all sources, deduplicates IPs and makes restricted additive', () => {
  const files = buildLists(fixture());
  assert.equal(files['blocklist.txt'], '198.51.100.0/24\n203.0.113.1\n203.0.113.3\n');
  assert.equal(files['blocklist-with-restricted.txt'], '198.51.100.0/24\n203.0.113.1\n203.0.113.2\n203.0.113.3\n203.0.113.4\n');
  const reordered = fixture(); reordered.items.reverse(); reordered.serverRules.reverse();
  assert.deepEqual(buildLists(reordered), files);
});
test('rejects partial, empty, malformed and unexpected records', () => {
  for (const data of [{}, {items:[],derivedItems:[],serverRules:[]}]) assert.throws(() => buildLists(data));
  for (const value of ['Any','1.2.3.999','01.2.3.4','1.2.3.4\n5.6.7.8']) {
    const data=fixture(); data.items[0].value=value; assert.throws(() => buildLists(data));
  }
  for (const value of ['203.0.113.3:0','203.0.113.3:65536','203.0.113.3:27015:1']) {
    const data=fixture(); data.serverRules[0].value=value; assert.throws(() => buildLists(data));
  }
  const data=fixture(); data.items[0].category='unknown'; assert.throws(() => buildLists(data));
});
