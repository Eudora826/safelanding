# SafeLanding AI Data Dictionary

## Relationships

- One scam pattern can link to many reference cases through shared `Knowledge_Gaps`, `Subcategory`, and retrieval similarity.
- One knowledge gap can be exploited by many patterns through `Related_Patterns`.
- User reports are stored separately from reference cases and always start with `Review_Status: Pending`.

## Layer 1: Real Scam Cases

| Field | Description | Example |
| --- | --- | --- |
| `Case_ID` | Stable case identifier. | `HS001` |
| `Title` | Short human-readable case title. | `Amsterdam fake landlord asks for deposit before viewing` |
| `Source_Name` | Source where the case came from. | `Hackathon starter dataset` |
| `Source_URL` | Evidence link for the case. | `https://...` |
| `Country` | Country where the scam targets students. | `Netherlands` |
| `City` | City associated with the offer or victim. | `Amsterdam` |
| `Target_Group` | Intended victim group. | `International Students` |
| `Scam_Category` | Top-level scam category. | `Housing Scam` |
| `Subcategory` | Specific housing scam subtype. | `Fake landlord` |
| `Threat_Actor` | Claimed or actual scammer role. | `Fake landlord` |
| `Communication_Channel` | Main channel used by the scammer. | `WhatsApp` |
| `Attack_Steps` | Ordered steps in the scam flow. | `["Posts attractive listing", "Requests deposit"]` |
| `Knowledge_Gaps` | Gap IDs exploited by the case. | `["KG001"]` |
| `Social_Engineering_Techniques` | Persuasion tactics used. | `["Scarcity", "Urgency"]` |
| `Requested_Action` | What the scammer wants the student to do. | `Pay deposit before viewing` |
| `Impact` | Likely harm to the student. | `Loss of deposit` |
| `Red_Flags` | Warning signals for detection. | `["Payment before viewing"]` |
| `Summary` | One-paragraph case summary. | `A fake landlord...` |

## Layer 2: Scam Patterns

| Field | Description |
| --- | --- |
| `Pattern_ID` | Stable pattern identifier, e.g. `SP001`. |
| `Pattern_Name` | Generalized scam template name. |
| `Description` | How the pattern works. |
| `Typical_Threat_Actor` | Common actor role used in the scam. |
| `Common_Channels` | Channels where the pattern appears. |
| `Trigger_Phrases` | Phrases useful for retrieval and warning generation. |
| `Knowledge_Gaps` | Gap IDs commonly exploited. |
| `Red_Flags` | Common warning signs. |
| `Recommended_Actions` | Safety guidance the chatbot can reuse. |

## Layer 3: Knowledge Gaps

| Field | Description |
| --- | --- |
| `Gap_ID` | Stable knowledge-gap identifier, e.g. `KG001`. |
| `Gap_Name` | Human-readable vulnerability theme. |
| `Description` | What the student may not know. |
| `Why_It_Matters` | Why this gap creates scam risk. |
| `Safe_Guidance` | Practical advice for the chatbot to give. |
| `Related_Patterns` | Pattern IDs associated with the gap. |

## Layer 4: User Reports

User reports are intake records for real scam reporting. They are not verified evidence until reviewed.

| Field | Description | Allowed Values |
| --- | --- | --- |
| `Report_ID` | Stable report identifier. | Generated, e.g. `UR0001` |
| `Timestamp` | UTC ingestion timestamp. | ISO 8601 |
| `Title` | Short report title. | Free text |
| `Description` | Student-provided report text. | Free text |
| `Scam_Category` | Reported category. | Default: `Housing Scam` |
| `Rental_Offer_Type` | Type of housing offer being reported. | `Direct landlord`, `Roommate invite`, `Student sublet`, `Housing group admin`, `Rental agency`, `Other`, `Unknown` |
| `Location` | City or area. | Free text |
| `City` | City associated with the report when known. | Free text |
| `Listing_Address` | Address, street, building, or area claimed in the offer. | Free text |
| `Listing_URL` | Listing, agency, profile, or social media URL. | URL string |
| `First_Contact_Date` | Date when the reporter first contacted or was contacted by the offering person. | ISO date preferred |
| `Requested_Move_In_Date` | Claimed or requested move-in date. | ISO date preferred |
| `Offering_Person_Name` | Name or alias used by the landlord, roommate, subletter, admin, or agency contact. | Free text |
| `Offering_Person_Role` | Claimed role of the offering person. | Free text |
| `Offering_Contact_Method` | Type of contact detail provided. | `Phone`, `Email`, `WhatsApp`, `Telegram`, `Instagram`, `Facebook`, `Other` |
| `Offering_Contact_Value` | Phone number, email, username, handle, or profile URL used by the offering person. | Free text |
| `Communication_Channel` | Main channel where the scam happened. | Free text |
| `Communication_Channel_Other` | Reporter-supplied channel when they choose `Other`. | Free text |
| `Payment_Requested` | What payment was requested and why. | Free text |
| `Payment_Method` | Requested payment method or bank/payment account details if provided. | Free text |
| `Amount_Requested` | Amount the scammer asked for. | Free text or number |
| `Amount_Paid` | Amount actually paid by the reporter, if any. | Free text or number |
| `Uploaded_Text` | Optional copied message or listing text. | Free text |
| `Evidence_URLs` | Optional suspicious URLs, listing links, profile links, or hosted screenshots. | List of URL strings |
| `Evidence_Files` | Screenshot, PDF, chat export, or other local evidence metadata. | List of file metadata objects |
| `AI_OCR_Analysis` | Reserved field for future AI/OCR extraction or summary. | Free text |
| `Threat_Actor` | Claimed actor role. | Free text |
| `Red_Flags_Observed` | Warning signs noticed by the reporter. | List of strings |
| `Reporter_Notes` | Extra notes from the reporter or reviewer. | Free text |
| `Admin_Notes` | Internal admin review notes. | Free text |
| `Reporter_Feedback` | Feedback that can be sent to the reporter when the report is vague, incomplete, or likely false. | Free text |
| `Review_Status` | Manual review state. | `Pending`, `Verified`, `Rejected`, `Needs More Info`, `Likely False Alert` |
