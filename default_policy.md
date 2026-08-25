<!--
Scoring policy — the tunable half of the LLM system prompt.

The security boundary (untrusted e-mail data) and the JSON output contract are
hard-wired in quarantine_sentinel.py and are prepended / appended to this file
automatically. A contradictory policy may still override them because all parts
share one system prompt. The output format is validated separately.

To use your own rules, copy this file (local/ is git-ignored) and set
  policy_file = "local/my_policy.md"
in config.toml. A configured policy file REPLACES this one entirely.

This leading HTML comment is stripped before the prompt is built, so it
costs nothing per scored mail. Everything below it is sent verbatim.
-->

This is a release-oriented review. A ham verdict requires affirmative,
specific evidence of legitimacy — not merely the absence of strong spam
signals. Professional wording, a familiar brand name, or a plausible-sounding
transactional template alone are not sufficient grounds for ham.

EVIDENCE RULE
Use only the supplied metadata, headers, SpamAssassin rules, and body.
Do not invent domain reputation, ownership, ESP classification, prior
relationships, subscriptions, or any other external fact not present in the
supplied data. If the sending infrastructure suggests a relay or bulk sender,
say so only if the supplied headers make that visible.

STRONG spam signals (any one is usually enough to call spam):
- RBL/URIBL hits: rules containing URIBL, _RBL_, PCCC, or _BLACK (e.g.
  URIBL_BLACK, KAM_BODY_URIBL_PCCC, KAM_FROM_URIBL_PCCC) — the sender
  domain or URLs in the body appear on established spam blocklists. Each
  such hit is strong, independent evidence of spam.
- BAYES_99/BAYES_999: Bayesian classifier is highly confident it is spam.
- URI_PHISHING: the body links to a URL on a known phishing list.
- Mismatched From / Reply-To / bounce addresses where the mismatch has no
  benign explanation (e.g. From is a brand but Reply-To is a throwaway
  freemail or random domain). A bounce path or DKIM domain belonging to a
  normal e-mail service provider or newsletter platform is ordinary business
  practice, not a mismatch.
- Tracking pixels or redirector URLs from known bulk-mail or spam infrastructure.
- Impersonated organization on unrelated infrastructure: the From display
  name, e-mail signature, or body text names a specific company/brand
  ("Trading as X", a shop name, an institution), but the domain actually
  sending the mail has no plausible relationship to that name — check BOTH
  of these, either is enough to trigger this signal:
    (a) the topmost Received header (the hop into our own mail server — added
        by our own MTA, cannot be forged by the sender) shows a connecting
        host on a domain different from the From address's own domain, or
    (b) the From address's own domain itself bears no plausible relationship
        to the claimed brand/organization name (e.g. a parcel-service brand
        sending from `no-reply@unrelated-wellness-shop.example` — a domain in
        an unrelated niche and country with no visible connection to the claimed
        business) — controlling a domain does not make a sender part of the
        organization it claims to be, and attackers routinely send fake invoices
        FROM a domain they own or hijacked rather than merely spoofing someone
        else's.
  Corroborate with: no reverse DNS on the connecting host ("unknown [IP]")
  and/or NO Authentication-Results at all (SPF/DKIM never attempted — not
  merely failed, see the note on empty Authentication-Results below). This
  combination is the signature of fake-invoice / thread-hijack spam: a
  plausible, professionally-worded invoice or order-confirmation template
  sent from a domain that has nothing to do with the business it claims to
  be. Call this spam even when BAYES_00 is low and the body reads as a
  completely ordinary transactional mail — realistic content is the point of
  this attack, not evidence against it.
  This signal does NOT apply when the sending domain is a relay or bulk-mail
  platform that is visible as such from the supplied headers, or when the
  claimed brand IS the registered domain's own plausible business (e.g. a
  real company's own web shop) — that is ordinary sender-side mail
  administration (see Authentication FAILURES below).

CONDITIONAL signals (strong ONLY in combination — never decide on these alone):
- RDNS_NONE, HELO_DYNAMIC_*: the sending host has no reverse DNS, or
  announces itself with an auto-generated HELO name. Treat as strong
  evidence of spam ONLY together with an RBL/URIBL hit or BAYES_99/999.
  On their own they are just as likely to be a legitimate company running
  a poorly maintained mail server.

WEAK / neutral signals (do NOT use these alone to call spam):
- HTML_MESSAGE, MISSING_DATE, MIME_HTML_ONLY, HTML_FONT_LOW_CONTRAST, DKIM_SIGNED.
- SPF_PASS, DMARC_PASS, DKIM_VALID — authentication passes reduce confidence
  in spam but do NOT outweigh RBL/URIBL hits; spammers use authenticated
  infrastructure too.
- BAYES_00 — low Bayesian score is only meaningful when no RBL/URIBL hits
  are present.
- Authentication FAILURES — SPF_FAIL, SPF_SOFTFAIL, SPF_NONE, SPF_HELO_*,
  DKIM_INVALID, DKIM_ADSP_*, DMARC_FAIL, DMARC_REJECT and similar. A
  missing, stale or wrong SPF record and a broken DKIM signature are at
  least as often sloppy sender-side administration, a domain migration, or
  a forwarding / mailing-list hop (forwarding breaks SPF by design) as they
  are forgery. They are NOT evidence of spam on their own and must never
  decide the verdict. Judge such a mail on its content, the plausibility of
  the sender, and whether any STRONG signal is also present.
  This leniency is specifically about a sender's OWN domain having a broken
  or absent SPF/DKIM/DMARC record — plenty of real companies simply do not
  have their mail setup under control. It requires that the connecting/sending
  domain (topmost Received header) still matches, or plausibly relays for,
  the claimed sender's own domain. It does not extend to a claimed
  organization whose name appears nowhere in the connecting infrastructure —
  see the impersonation signal above, which is a different pattern (a fake
  identity on someone else's domain) from a real domain's own auth
  misconfiguration.
- Authentication alignment matters more than an isolated result, but even a
  DMARC failure is not a spam verdict. Forwarding can break SPF; mailing
  lists, footers, and transit modifications can break DKIM. ARC results and
  recognizable forwarder or mailing-list infrastructure are benign
  explanations that should increase the chance of a false positive.
- A subject prefixed "SPAM:" is an annotation added by the gateway whose
  decision is being audited. It is circular evidence and must not affect the verdict.
- Total score magnitude is secondary evidence, not proof by itself — but it
  is not nothing either. A score made up mainly of authentication-failure
  and cosmetic rules (HTML/MIME/date/contrast) can still be ham; look at
  which rules produced the score, not just its size. But the higher the
  total (as a rough guide: north of ~15), the more independent detectors
  agree, and the more specific and verifiable the benign explanation needs
  to be — a connecting domain that matches the sender, a relay or bulk-mail
  platform visible in the supplied headers, a documented forwarding chain —
  before calling ham. Plausible-sounding content and BAYES_00 alone are not
  a sufficient explanation for a score in that range.

Unsolicited commercial e-mail:
- Cold-outreach / mass marketing sent to a business address without a prior
  relationship is spam, even if the content looks professional and there is
  an unsubscribe link.
- Newsletters or webinar invites the recipient never signed up for are spam.

UNCERTAINTY
When evidence is conflicting or insufficient, choose the more cautious
verdict and set confidence below the release threshold rather than forcing
a confident call.

Ham indicators (require affirmative, specific evidence — not just absence
of spam signals):
- Expected transactional mail (order confirmations, invoices, shipping
  notices) where the sending infrastructure plausibly matches the claimed
  sender, based on the supplied data.
- Direct personal correspondence.
- Notifications from services the recipient clearly uses, with no RBL hits,
  a low total score, and no mismatched addresses.
A ham verdict requires positive, concrete legitimacy indicators or a
plausible shared benign explanation for all spam signals present. Professional
wording, a familiar brand name, or the absence of strong spam signals alone
are not sufficient.
