/**
 * The precision corpus.
 *
 * CLEAN cases must produce ZERO detections. SENSITIVE cases must each produce
 * the detector named alongside them. Shared by `bench/precision.mjs` (which
 * prints a report) and `test/precision.test.js` (which fails the build).
 *
 * The clean half is deliberately adversarial: it holds the shapes most likely to
 * trip a redactor — hex hashes, UUIDs, order and batch numbers, version strings,
 * dates and near-miss values — because a filter that destroys a legitimate order
 * number in a live support chat is worse than no filter at all.
 */

export const CLEAN = {
  'code identifiers': [
    'const id = "550e8400-e29b-41d4-a716-446655440000";',
    'commit 9f2b1c4e8a7d6039fedcba9876543210abcdef12 landed',
    'background: #A3C1DA; border: #ff00ff;',
    'upgraded from 1.2.3 to 10.44.201 last night',
    'listening on 127.0.0.1:8080 and 0.0.0.0:3000',
    'sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    // Assembled at runtime rather than written out. `AC` followed by 32 hex
    // characters is indistinguishable from a Twilio Account SID, and GitHub's
    // own push protection blocks the literal — which is exactly the collision
    // these two cases exist to document. A Twilio Account SID is a public
    // identifier anyway, not a credential, which is why the rule that matched
    // it was removed.
    'GIT SHA ' + 'AC' + '1234567890ABCDEF'.repeat(2) + '12 built ok',
    'docker image sha ' + 'AC' + '0123456789abcdef'.repeat(2) + ' ready',
  ],
  commerce: [
    'Order #100-2039-4471 shipped on Tuesday',
    'Invoice INV-2026-0098231 is now paid',
    'Tracking number 1Z999AA10123456784 with UPS',
    'SKU 4820-9931-0027 is out of stock',
    'Your order 4111 1111 1111 1112 could not be found',
    'Reference 100 20 3000 in the ledger',
    'Batch 372 45 9912 processed',
  ],
  'numbers in prose': [
    'Revenue grew 45% to 1,250,000 in Q3 2026',
    'The meeting is at 14:30 on 2026-09-20',
    'It weighs 1200 grams and costs 39.99 euros',
    'We shipped 5558675309 events last month',
    'Between 2019 and 2026 the figure tripled',
    'Room 405, floor 12, building 3',
  ],
  'non-sensitive identifiers': [
    'ISBN 978-3-16-148410-0 is the second edition',
    'License plate ABC 123 registered',
    'Serial 372-8891-0021 on the back panel',
    'Flight BA 2490 departs at noon',
  ],
  'natural prose': [
    'The quick brown fox jumps over the lazy dog repeatedly.',
    'Cafe naive resume: accented words such as cafe, naive and resume.',
    'هذا نص عربي عادي لا يحتوي على أي بيانات حساسة على الإطلاق.',
    '日本語のテキストです。機密情報は含まれていません。',
    'Ceci est un texte francais tout a fait ordinaire.',
  ],
  'markdown and urls': [
    'See [the docs](https://example.com/guide?page=2#section) for details',
    'Run `npm install express@4.18.2` then restart',
    '| col a | col b |\n| --- | --- |\n| 1 | 2 |',
    'Visit https://api.service.io/v1/users/12345/profile now',
  ],
  'near-miss sensitive': [
    'contact us @support or @sales for help',
    'the host is db-primary@cluster internal only',
    'IBAN GB82 WEST 1234 5698 7654 33 is invalid',
    'card 1234 5678 9012 3456 was declined',
    'sk-8 and sk-short are model names',
  ],
};

export const SENSITIVE = [
  ['email', 'write to jane.doe@acme-corp.com today'],
  ['email', 'first+tag@sub.domain.org bounced'],
  ['creditCard', 'card 4111 1111 1111 1111 charged'],
  ['creditCard', 'card 5500-0000-0000-0004 on file'],
  ['creditCard', 'card 4111 1111 1111 1111 (nbsp)'],
  ['secret', 'key sk-abcdefghijklmnopqrstuvwxyz123456 here'],
  ['secret', 'key sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789 here'],
  ['secret', 'aws AKIAIOSFODNN7EXAMPLE creds'],
  ['secret', 'gh ghp_abcdefghijklmnopqrstuvwxyz0123456789 token'],
  ['secret', 'stripe sk_live_abcdefghij0123456789 key'],
  ['secret', '-----BEGIN RSA PRIVATE KEY-----\nMIIEvQIBADANBgkq\n-----END RSA PRIVATE KEY-----'],
  ['ssn', 'ssn 123-45-6789 on file'],
  ['iban', 'iban GB82 WEST 1234 5698 7654 32 verified'],
  ['phone', 'call 555-867-5309 now'],
  ['phone', 'call +1 555 867 5309 now'],
];

export const cleanCount = Object.values(CLEAN).reduce((n, v) => n + v.length, 0);
