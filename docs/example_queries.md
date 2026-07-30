# Example Retrieval Queries

## Query 1

```text
Landlord asks me to pay deposit before viewing
```

Expected retrieval:

- Pattern: `SP001` Fake Landlord Deposit Request
- Knowledge gaps: `KG001` Dutch Rental Deposit Rules, `KG004` Room Viewing Practices
- Related cases: `HS001`, `HS011`, `HS007`
- Red flags: payment before viewing, pressure to decide, no live viewing

## Query 2

```text
A student says they are leaving for exchange and wants me to pay to hold a sublet
```

Expected retrieval:

- Pattern: `SP003` Fake Student Sublet
- Knowledge gaps: `KG003` Subletting Rules, `KG001` Dutch Rental Deposit Rules
- Related cases: `HS002`, `HS009`
- Red flags: no sublet permission, no contract, no registration possible

## Query 3

```text
Someone in a housing Facebook group says they are an admin and sent me a payment link
```

Expected retrieval:

- Pattern: `SP004` Fake Housing Group Administrator
- Knowledge gaps: `KG006` Housing Platform Trustworthiness, `KG002` Student Housing Allocation Process
- Related case: `HS006`
- Red flags: private admin message, external payment link, no public verification

## Query 4

```text
An agency website guarantees a room if I pay a registration fee today
```

Expected retrieval:

- Pattern: `SP005` Fake Rental Agency
- Knowledge gaps: `KG006` Housing Platform Trustworthiness, `KG001` Dutch Rental Deposit Rules
- Related cases: `HS004`, `HS008`, `HS012`
- Red flags: guaranteed room, upfront fee, cloned or recently created website

## Query 5

```text
Is +31 6 1234 5678 a scam?
```

Expected retrieval when the phone number exists in user reports:

- If a matching report is `Verified`, directly warn that the identifier has a verified scam report.
- If matching reports are only `Pending`, show that the identifier has been reported before and is pending review.
- Include matching report counts in `reported_scam_intelligence`.
