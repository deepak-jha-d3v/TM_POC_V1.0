"""
generate_investigation_data.py
-------------------------------
Builds output/investigation_data.json -- a per-customer bundle of every data
point the L1 investigation workspace needs (KYC/CDD, transaction analysis,
historical behaviour, AML history, PEP, sanctions, OSINT/adverse media, UBO,
red-flag analysis, recommendation, audit trail, SLA) -- generated from, and
kept consistent with, the existing customers.csv / accounts.csv /
transactions.csv / alerts_for_ui.json so the same customer ID, account
numbers, transactions and risk rating line up across every section of the
investigation page.

Deterministic: every customer's dummy data is seeded from their customer_id,
so re-running this script produces byte-identical output.
"""

import csv
import hashlib
import json
import random
from collections import defaultdict
from datetime import datetime, timedelta

TODAY = datetime(2026, 7, 3)

# ---------------------------------------------------------------- load base data
def load_csv(path):
    with open(path, newline="") as f:
        return list(csv.DictReader(f))

customers = {c["customer_id"]: c for c in load_csv("data/customers.csv")}
accounts_by_cust = defaultdict(list)
for a in load_csv("data/accounts.csv"):
    accounts_by_cust[a["customer_id"]].append(a)

txns_by_cust = defaultdict(list)
for t in load_csv("data/transactions.csv"):
    txns_by_cust[t["customer_id"]].append(t)
for cid in txns_by_cust:
    txns_by_cust[cid].sort(key=lambda t: t["timestamp"])

alerts = json.load(open("output/alerts_for_ui.json"))
alerts_by_cust = defaultdict(list)
for a in alerts:
    alerts_by_cust[a["customer_id"]].append(a)

# ---------------------------------------------------------------- reference pools
FIRST_NAMES = ["Elena", "Marcus", "Priya", "Wei", "Fatima", "Diego", "Anya",
               "Kwame", "Sofia", "Rahul", "Ingrid", "Tomas", "Layla", "Hiro",
               "Chidi", "Freya", "Omar", "Nadia", "Lucas", "Amara"]
LAST_NAMES = ["Whitfield", "Okonkwo", "Petrov", "Nakamura", "Alvarez",
              "Marchetti", "Haddad", "Lindqvist", "Osei", "Kowalski",
              "Fontaine", "Ibrahim", "Novak", "Sundaram", "Bergström"]
EMPLOYERS = ["Meridian Global Trading Ltd", "Northbridge Logistics Group",
             "Aurex Consulting Partners", "Silverline Manufacturing Co",
             "Vantage Point Holdings", "Continental Freight & Marine",
             "Bluepeak Capital Advisors", "Estelle & Co Trading House",
             "Harborview Import Export", "Kestrel Resources Group"]
INDUSTRIES = ["Import/Export Trading", "Real Estate", "Construction",
              "Retail & Wholesale", "IT Services", "Hospitality",
              "Precious Metals & Jewellery", "Freight & Logistics",
              "Consulting Services", "Manufacturing"]
INCOME_RANGES = ["USD 30,000 - 50,000", "USD 50,000 - 100,000",
                  "USD 100,000 - 250,000", "USD 250,000 - 500,000",
                  "USD 500,000+"]
SOURCE_OF_WEALTH = ["Salaried employment", "Business ownership / profits",
                     "Inheritance", "Sale of property", "Investment returns",
                     "Family gift", "Retained business earnings"]
CUSTOMER_SEGMENTS = ["Retail Mass Market", "Retail Affluent", "Private Banking",
                      "SME Business Banking", "Corporate Banking"]
PRODUCTS = ["Current Account", "Savings Account", "Fixed Deposit", "Credit Card",
            "Trade Finance Facility", "Wire Transfer Service", "FX Trading",
            "Business Loan", "Investment Account", "Crypto Custody"]
HIGH_RISK_COUNTRIES = ["Cayman Islands", "Russia", "Iran", "Myanmar", "Panama",
                        "North Korea", "Venezuela", "Syria"]
COUNTRY_NAMES = {"FR": "France", "NL": "Netherlands", "SG": "Singapore",
                  "GB": "United Kingdom", "US": "United States", "AE": "UAE",
                  "DE": "Germany", "CA": "Canada", "CH": "Switzerland",
                  "IN": "India", "CN": "China", "AU": "Australia",
                  "HK": "Hong Kong", "BR": "Brazil", "ZA": "South Africa",
                  "RU": "Russia", "KY": "Cayman Islands", "PA": "Panama",
                  "MM": "Myanmar", "IR": "Iran", "VE": "Venezuela",
                  "SY": "Syria", "KP": "North Korea"}
PEP_POSITIONS = ["Deputy Minister of Trade", "Regional Governor",
                  "Member of Parliament", "State-Owned Enterprise Chairman",
                  "Central Bank Board Member", "Municipal Mayor",
                  "Head of Customs Authority", "Senior Judge"]
NEWS_PUBLICATIONS = ["Reuters", "Bloomberg", "Financial Times", "The Straits Times",
                      "Al Jazeera", "The Guardian", "Nikkei Asia", "AFP",
                      "Local Business Journal", "Global Compliance News"]
TAGS_POOL = ["Money Laundering", "Fraud", "Tax Evasion", "Shell Company",
             "Corruption", "Terror Financing", "Drug Trafficking", "Bribery",
             "Cyber Crime", "High Risk Country"]
SANCTIONS_LISTS = ["OFAC SDN List", "UN Security Council Consolidated List",
                    "EU Consolidated Sanctions List", "UK HMT Sanctions List"]
INVESTIGATORS = ["R. Alvarez (L2)", "S. Tanaka (L2)", "M. Okafor (L1)",
                  "J. Petrov (L2)", "A. Haddad (L1)", "K. Lindqvist (L2)"]
RELATIONSHIP_TYPES = ["Spouse", "Business Partner", "Sibling", "Adult Child",
                       "Nominee Director", "Beneficiary"]
CDD_STATUSES = ["Approved", "Approved - Conditions Apply", "Pending Refresh"]

DECISION_LABELS = {
    "close_false_positive": "Close as False Positive",
    "escalate_to_l2": "Escalate to L2 Investigator",
    "request_more_info": "Request Additional Information",
}

# ---------------------------------------------------------------- helpers
def rng_for(customer_id, salt=""):
    seed = int(hashlib.sha256((customer_id + salt).encode()).hexdigest(), 16) % (2**32)
    return random.Random(seed)

def fmt_date(dt):
    return dt.strftime("%Y-%m-%d")

def pick_name(r):
    return f"{r.choice(FIRST_NAMES)} {r.choice(LAST_NAMES)}"

def mask_doc(r, prefix, length):
    return prefix + "".join(r.choice("0123456789") for _ in range(length))

def gen_kyc(cust, r, is_corporate):
    dob_year = r.randint(1958, 2001)
    dob = f"{dob_year}-{r.randint(1,12):02d}-{r.randint(1,28):02d}"
    customer_since_year = int(cust["kyc_date"][:4])
    kyc_last_reviewed = TODAY - timedelta(days=r.randint(30, 340))
    next_review = kyc_last_reviewed + timedelta(days=365)
    risk_rating = cust["risk_rating"]
    edd_required = risk_rating == "high" or r.random() < 0.15
    turnover = r.choice(["USD 500,000 - 1,000,000", "USD 1,000,000 - 5,000,000",
                          "USD 5,000,000 - 20,000,000"]) if is_corporate else "N/A"
    country_name = COUNTRY_NAMES.get(cust["country"], cust["country"])
    return {
        "full_name": cust["name"],
        "dob": dob,
        "nationality": country_name,
        "gender": r.choice(["Male", "Female"]),
        "occupation": cust["occupation"],
        "employer": r.choice(EMPLOYERS) if not is_corporate else cust["name"],
        "income_range": r.choice(INCOME_RANGES),
        "annual_turnover": turnover,
        "source_of_wealth": r.choice(SOURCE_OF_WEALTH),
        "source_of_funds": r.choice(["Business trading income", "Employment salary",
                                       "Investment portfolio proceeds", "Trade receivables"]),
        "tax_residency": country_name,
        "customer_category": "Corporate / Business" if is_corporate else "Individual / Retail",
        "identification": {
            "passport": {"number": mask_doc(r, "P", 8), "expiry": fmt_date(TODAY + timedelta(days=r.randint(200, 1800))), "status": "Verified"},
            "national_id": {"number": mask_doc(r, "N", 9), "expiry": fmt_date(TODAY + timedelta(days=r.randint(200, 1800))), "status": "Verified"},
            "pan": {"number": mask_doc(r, "PAN", 6), "expiry": "N/A", "status": r.choice(["Verified", "Not Provided"])},
            "driving_license": {"number": mask_doc(r, "DL", 8), "expiry": fmt_date(TODAY + timedelta(days=r.randint(-60, 900))), "status": r.choice(["Verified", "Expired", "Not Provided"])},
        },
        "address": {
            "permanent": f"{r.randint(1,240)} {r.choice(['Marina','Kings','Elm','Harbour','Victoria','Orchard'])} {r.choice(['Street','Road','Avenue','Boulevard'])}, {country_name}",
            "correspondence": f"{r.randint(1,240)} {r.choice(['Marina','Kings','Elm','Harbour','Victoria','Orchard'])} {r.choice(['Street','Road','Avenue','Boulevard'])}, {country_name}",
            "country": country_name,
        },
        "risk_rating": risk_rating,
        "kyc_last_reviewed": fmt_date(kyc_last_reviewed),
        "next_review_date": fmt_date(next_review),
        "customer_since": f"{customer_since_year}-{cust['kyc_date'][5:7]}-{cust['kyc_date'][8:10]}",
        "cdd_status": r.choice(CDD_STATUSES),
        "edd_required": "Y" if edd_required else "N",
    }

def gen_risk_snapshot(cust, r, kyc, accounts, cust_alerts, is_corporate):
    years = TODAY.year - int(cust["kyc_date"][:4])
    overall_score = max(a["rule_based_score"] for a in cust_alerts) if cust_alerts else r.randint(20, 45)
    return {
        "risk_rating": cust["risk_rating"],
        "customer_type": "Corporate" if is_corporate else "Individual",
        "occupation": cust["occupation"],
        "nationality": kyc["nationality"],
        "residence_country": kyc["nationality"],
        "industry": r.choice(INDUSTRIES) if is_corporate else "N/A",
        "years_with_bank": max(years, 1),
        "customer_segment": r.choice(CUSTOMER_SEGMENTS),
        "products_held": r.sample(PRODUCTS, k=r.randint(2, 5)),
        "total_accounts": len(accounts),
        "total_alerts": len(cust_alerts),
        "previous_sar_count": r.choice([0, 0, 0, 1, 2]) if cust["risk_rating"] == "high" else r.choice([0, 0, 0, 0, 1]),
        "last_alert_date": fmt_date(TODAY - timedelta(days=r.randint(1, 9))),
        "overall_risk_score": overall_score,
    }

def gen_transaction_analysis(cust_id, r, cust_txns, accounts):
    window = cust_txns[-50:] if len(cust_txns) > 50 else cust_txns
    purposes = ["Goods payment", "Salary credit", "Family support", "Invoice settlement",
                "Rent payment", "Loan repayment", "Trade settlement", "Personal transfer",
                "Investment funding", "Refund", "Service fee"]
    enriched = []
    monthly_volume = defaultdict(int)
    monthly_value = defaultdict(float)
    country_dist = defaultdict(int)
    channel_dist = defaultdict(int)
    for t in window:
        month = t["timestamp"][:7]
        monthly_volume[month] += 1
        amt = float(t["amount"])
        monthly_value[month] += amt
        country_dist[t["counterparty_country"]] += 1
        channel_dist[t["channel"]] += 1
        risk_ind = "-"
        if amt >= 9000 and amt < 10000:
            risk_ind = "Near CTR threshold"
        elif t["counterparty_country"] in HIGH_RISK_COUNTRIES:
            risk_ind = "High-risk jurisdiction"
        elif amt % 1000 == 0 and amt >= 5000:
            risk_ind = "Round amount"
        enriched.append({
            "date": t["timestamp"][:10],
            "amount": round(amt, 2),
            "currency": t["currency"],
            "direction": t["direction"],
            "counterparty": t["counterparty"],
            "country": t["counterparty_country"],
            "channel": t["channel"],
            "purpose": r.choice(purposes),
            "risk_indicator": risk_ind,
        })
    triggering = enriched[-1] if enriched else None
    return {
        "triggering_transaction": triggering,
        "history": list(reversed(enriched)),
        "monthly_volume": dict(sorted(monthly_volume.items())),
        "monthly_value": {k: round(v, 2) for k, v in sorted(monthly_value.items())},
        "country_distribution": dict(country_dist),
        "channel_distribution": dict(channel_dist),
    }

def gen_historical_behaviour(cust, r, txn_analysis):
    expected_salary = float(cust["expected_monthly_volume"])
    actual_credits = sum(t["amount"] for t in txn_analysis["history"] if t["direction"] == "credit")
    n_months = max(len(txn_analysis["monthly_volume"]), 1)
    actual_monthly_avg_credit = actual_credits / n_months if n_months else actual_credits
    expected_transfers = r.randint(6, 14)
    actual_transfers = len(txn_analysis["history"])
    observed_countries = sorted(set(t["country"] for t in txn_analysis["history"]))
    home_country = COUNTRY_NAMES.get(cust["country"], cust["country"])
    deviation_flags = []
    if actual_monthly_avg_credit > expected_salary * 2:
        deviation_flags.append("Monthly credit volume significantly exceeds expected salary/turnover")
    if actual_transfers > expected_transfers * 3:
        deviation_flags.append("Transaction frequency far exceeds expected activity level")
    extra_countries = [c for c in observed_countries if COUNTRY_NAMES.get(c, c) != home_country]
    if len(extra_countries) >= 2:
        deviation_flags.append("Cross-border activity spans multiple jurisdictions outside expected profile")
    return {
        "expected_monthly_credit": round(expected_salary, 2),
        "actual_monthly_credit": round(actual_monthly_avg_credit, 2),
        "expected_monthly_transfers": expected_transfers,
        "actual_monthly_transfers": round(actual_transfers / n_months, 1),
        "expected_countries": [home_country],
        "observed_countries": [COUNTRY_NAMES.get(c, c) for c in observed_countries] or [home_country],
        "deviation_flags": deviation_flags,
    }

def gen_aml_history(cust_id, cust, r, accounts, cust_alerts):
    has_history = r.random() < (0.55 if cust["risk_rating"] == "high" else 0.25)
    investigations = []
    if has_history:
        for i in range(r.randint(1, 3)):
            date = TODAY - timedelta(days=r.randint(60, 900))
            investigations.append({
                "alert_id": f"ALT-{cust_id}-H{i+1}",
                "rule": r.choice(["R01_STRUCTURING", "R06_HIGH_RISK_COUNTRIES", "R09_DORMANT_ACCOUNT",
                                    "R05_FLOW_THROUGH", "R03_UNUSUAL_SPENDING"]),
                "date": fmt_date(date),
                "outcome": r.choice(["Closed - False Positive", "Closed - No Action",
                                       "Escalated - SAR Filed", "Closed - Customer Exited"]),
                "investigator": r.choice(INVESTIGATORS),
                "case_number": f"CASE-{r.randint(100000,999999)}",
            })
        investigations.sort(key=lambda x: x["date"], reverse=True)
    ip_pool = [f"{r.randint(10,223)}.{r.randint(0,255)}.{r.randint(0,255)}.{r.randint(1,254)}" for _ in range(r.randint(2,4))]
    device_pool = [f"DEV-{mask_doc(r,'',10)}" for _ in range(r.randint(1,3))]
    login_countries = [cust["country"]] + (r.sample(list(COUNTRY_NAMES.keys()), k=r.randint(0,2)))
    customer_level = {
        "previous_ip_addresses": ip_pool,
        "device_ids": device_pool,
        "login_countries": sorted(set(login_countries)),
        "login_time_pattern": r.choice(["Consistent business hours (09:00-18:00 local)",
                                          "Irregular, frequently late-night logins",
                                          "Consistent early-morning logins", "No unusual pattern detected"]),
    }
    account_level = []
    for acc in accounts:
        account_level.append({
            "account_id": acc["account_id"],
            "relationship_type": r.choice(["Primary Holder", "Joint Holder", "Authorized Signatory"]),
            "joint_account": r.choice(["Y", "N"]),
            "beneficiaries": r.sample([pick_name(r) for _ in range(2)], k=1) if r.random() < 0.3 else [],
            "linked_customers": [f"CUST{r.randint(1,90):04d}" for _ in range(r.randint(0,1))],
            "account_description": r.choice(["Day-to-day operating account", "Payroll disbursement account",
                                               "Trade settlement account", "Personal savings account",
                                               "Business working capital account"]),
        })
    return {
        "history_available": "Y" if has_history else "N",
        "previous_investigations": investigations,
        "customer_history": customer_level,
        "account_history": account_level,
    }

def gen_pep(cust, r):
    is_pep = r.random() < (0.30 if cust["risk_rating"] == "high" else 0.06)
    if not is_pep:
        return {"pep_flag": "N", "matches": []}
    match = {
        "person_name": cust["name"],
        "position": r.choice(PEP_POSITIONS),
        "country": COUNTRY_NAMES.get(cust["country"], cust["country"]),
        "relationship_type": r.choice(["Self", "Close Associate", "Family Member"]),
        "match_score": r.randint(78, 99),
        "screening_date": fmt_date(TODAY - timedelta(days=r.randint(1, 30))),
        "source": r.choice(["World-Check", "Dow Jones Risk & Compliance", "Refinitiv PEP Database"]),
    }
    return {"pep_flag": "Y", "matches": [match]}

def gen_sanctions(cust, r):
    is_match = r.random() < (0.12 if cust["risk_rating"] == "high" else 0.02)
    if not is_match:
        return {"sanctions_match": "N", "matches": []}
    match = {
        "list_name": r.choice(SANCTIONS_LISTS),
        "match_percent": r.randint(70, 96),
        "alias": cust["name"].split()[0] + " " + r.choice(LAST_NAMES),
        "country": r.choice(HIGH_RISK_COUNTRIES),
        "screening_date": fmt_date(TODAY - timedelta(days=r.randint(1, 30))),
        "source": r.choice(SANCTIONS_LISTS),
    }
    return {"sanctions_match": "Y", "matches": [match]}

def gen_osint(cust, r, is_corporate, pep_flag):
    n = r.randint(5, 10)
    subjects = []
    if is_corporate:
        subjects = [cust["name"], f"{cust['name']} Director", "Ultimate Beneficial Owner"]
    else:
        subjects = [cust["name"]] + (["politically exposed person"] if pep_flag == "Y" else [])
    headlines_templates = [
        "{subj} named in {country} regulatory probe over {tag_l}",
        "Local authorities investigate {subj} for suspected {tag_l}",
        "{subj} linked to offshore structure amid {tag_l} concerns",
        "Report raises {tag_l} questions over {subj} dealings",
        "{subj} business associate charged in {tag_l} case",
        "Industry watchdog flags {subj} for {tag_l} risk indicators",
        "{subj} unaffected as sector-wide {tag_l} review continues",
        "{subj} featured in industry award for community initiatives",
        "{subj} completes routine regulatory filing with no findings",
        "{subj} expands operations following successful funding round",
    ]
    articles = []
    negative_count = 0
    for i in range(n):
        subj = r.choice(subjects)
        tag = r.choice(TAGS_POOL)
        template = r.choice(headlines_templates)
        is_negative = "no findings" not in template and "award" not in template and "funding round" not in template
        headline = template.format(subj=subj, tag_l=tag.lower(), country=r.choice(list(COUNTRY_NAMES.values())))
        sentiment = "Negative" if is_negative else "Neutral" if "no findings" in template else "Positive"
        if sentiment == "Negative":
            negative_count += 1
        articles.append({
            "headline": headline,
            "publication": r.choice(NEWS_PUBLICATIONS),
            "date": fmt_date(TODAY - timedelta(days=r.randint(10, 720))),
            "country": r.choice(list(COUNTRY_NAMES.values())),
            "risk_category": tag if is_negative else "None",
            "summary": f"Coverage discusses {subj}'s association with an ongoing industry review "
                        f"related to {tag.lower()} concerns raised by regional regulators." if is_negative else
                        f"Routine coverage of {subj} with no adverse findings reported.",
            "sentiment": sentiment,
            "tags": [tag] if is_negative else [],
        })
    return {
        "negative_news": "Y" if negative_count >= 2 else "N",
        "negative_article_count": negative_count,
        "articles": articles,
    }

def gen_ubo(cust, r, is_corporate):
    if not is_corporate:
        return None
    n = r.randint(2, 4)
    remaining = 100
    shareholders = []
    for i in range(n):
        if i == n - 1:
            pct = remaining
        else:
            hi = max(10, min(45, remaining - (n - i - 1) * 5))
            pct = r.randint(10, hi)
            remaining -= pct
        shareholders.append({
            "shareholder": pick_name(r) if r.random() < 0.7 else f"{r.choice(LAST_NAMES)} Holdings {r.choice(['Ltd','SA','BV','LLC'])}",
            "ownership_percent": pct,
            "country": r.choice(list(COUNTRY_NAMES.values())),
            "risk_rating": r.choices(["low", "medium", "high"], weights=[5,3,1])[0],
            "pep_flag": r.choices(["N", "Y"], weights=[9,1])[0],
            "sanctions_flag": r.choices(["N", "Y"], weights=[19,1])[0],
        })
    shareholders.sort(key=lambda s: -s["ownership_percent"])
    return {"entity_name": cust["name"], "shareholders": shareholders}

RED_FLAG_DEFS = [
    ("round_amounts", "Round Amounts"),
    ("rapid_movement", "Rapid Movement"),
    ("layering", "Layering"),
    ("structuring", "Structuring"),
    ("cash_intensive", "Cash Intensive"),
    ("dormant_account", "Dormant Account"),
    ("high_risk_jurisdiction", "High Risk Jurisdiction"),
    ("unrelated_third_party", "Unrelated Third Party"),
    ("crypto_exposure", "Crypto Exposure"),
    ("shell_company", "Shell Company"),
    ("velocity", "Velocity"),
    ("large_cash", "Large Cash"),
    ("cross_border", "Cross Border"),
]

def gen_red_flags(cust, r, txn_analysis, cust_alerts, is_corporate):
    triggered_rule_ids = {rt["rule_id"] for a in cust_alerts for rt in a["rules_triggered"]}
    hist = txn_analysis["history"]
    round_amt_count = sum(1 for t in hist if t["amount"] % 500 == 0 and t["amount"] >= 2000)
    countries_used = set(t["country"] for t in hist)
    high_risk_hits = [c for c in countries_used if c in HIGH_RISK_COUNTRIES]
    cash_txns = [t for t in hist if t["channel"] == "cash"]
    flags = {}
    flags["round_amounts"] = (round_amt_count >= 3, f"{round_amt_count} round-value transactions observed in the review window", 10)
    flags["rapid_movement"] = (any("R05" in rid for rid in triggered_rule_ids), "Large inbound transfer largely moved out again within 48 hours" if any("R05" in rid for rid in triggered_rule_ids) else "No disproportionate pass-through pattern detected", 20)
    flags["layering"] = (any(rid.startswith(("R10", "R11")) for rid in triggered_rule_ids), "Repeated asset-type conversions / round-tripping detected" if any(rid.startswith(("R10","R11")) for rid in triggered_rule_ids) else "No layering pattern detected", 20)
    flags["structuring"] = (any(rid.startswith(("R01", "R12")) for rid in triggered_rule_ids), "Multiple deposits just under the CTR reporting threshold" if any(rid.startswith(("R01","R12")) for rid in triggered_rule_ids) else "No structuring pattern detected", 25)
    flags["cash_intensive"] = (any(rid.startswith("R08") for rid in triggered_rule_ids), "Cash volume disproportionate to expected activity" if any(rid.startswith("R08") for rid in triggered_rule_ids) else "Cash usage within expected range", 15)
    flags["dormant_account"] = (any(rid.startswith("R09") for rid in triggered_rule_ids), "Extended inactivity followed by a burst of transactions" if any(rid.startswith("R09") for rid in triggered_rule_ids) else "No dormancy pattern detected", 10)
    flags["high_risk_jurisdiction"] = (len(high_risk_hits) > 0, f"Counterparties located in {', '.join(COUNTRY_NAMES.get(c,c) for c in high_risk_hits)}" if high_risk_hits else "No high-risk jurisdiction exposure found", 25)
    flags["unrelated_third_party"] = (r.random() < 0.25, "Funds received from or sent to a counterparty with no apparent relationship to the customer" if True else "", 15)
    crypto_present = any(a.get("crypto_transaction_count", 0) > 0 for a in cust_alerts)
    flags["crypto_exposure"] = (crypto_present, "Customer has crypto asset activity, including exchange/private wallet transfers" if crypto_present else "No crypto exposure identified", 15)
    flags["shell_company"] = (is_corporate and r.random() < 0.2, "Corporate structure shows limited operating substance for its stated business purpose" if is_corporate else "Not applicable - retail customer", 20)
    flags["velocity"] = (len(hist) > 40, f"{len(hist)} transactions observed in the review window, above typical volume", 15)
    flags["large_cash"] = (any(t["amount"] > 8000 and t["channel"] == "cash" for t in hist), "Large cash transaction(s) exceeding typical profile", 20)
    flags["cross_border"] = (len(countries_used) >= 3, f"Activity spans {len(countries_used)} distinct countries", 10)

    # fix unrelated_third_party reason text (avoid ternary-with-True artifact)
    if flags["unrelated_third_party"][0]:
        flags["unrelated_third_party"] = (True, "Counterparty relationship to customer could not be established from account records", 15)
    else:
        flags["unrelated_third_party"] = (False, "All counterparties consistent with customer's known relationships", 15)

    result = []
    for key, label in RED_FLAG_DEFS:
        triggered, reason, weight = flags[key]
        result.append({"flag": label, "triggered": "Y" if triggered else "N", "reason": reason, "weight": weight})
    return result

def gen_recommendation(cust_alerts, red_flags, aml_history, pep, sanctions, osint):
    total_weight = sum(f["weight"] for f in red_flags if f["triggered"] == "Y")
    max_ai_score = max((a["ai_copilot"]["confidence_score"] for a in cust_alerts), default=0)
    reasons = []
    if sanctions["sanctions_match"] == "Y":
        decision = "Potential SAR"
        reasons.append("A sanctions list match was identified and must be escalated regardless of other factors.")
    elif total_weight >= 60 or max_ai_score >= 85:
        decision = "Potential SAR"
        reasons.append(f"Cumulative red-flag weight of {total_weight} combined with an AI confidence score of {max_ai_score} indicates a high likelihood of genuine suspicious activity.")
    elif total_weight >= 35 or max_ai_score >= 65 or pep["pep_flag"] == "Y" or osint["negative_news"] == "Y":
        decision = "Escalate to L2"
        reasons.append(f"Cumulative red-flag weight of {total_weight}, together with supplementary screening results, warrants a second-level review before disposition.")
    elif total_weight >= 15:
        decision = "Need More Information"
        reasons.append(f"Some red-flag indicators are present (weight {total_weight}) but current evidence is insufficient to reach a confident disposition without further documentation.")
    else:
        decision = "Close Alert"
        reasons.append(f"Red-flag weight is low ({total_weight}) and no adverse screening results were identified; activity appears consistent with the customer's expected profile.")
    if pep["pep_flag"] == "Y":
        reasons.append("Customer or a close associate is a Politically Exposed Person, requiring enhanced scrutiny.")
    if osint["negative_news"] == "Y":
        reasons.append(f"{osint['negative_article_count']} adverse media article(s) were identified referencing the customer.")
    if aml_history["history_available"] == "Y":
        reasons.append("Customer has prior AML investigation history on file, which increases the weight given to new alerts.")
    return {"decision": decision, "explanation": reasons, "red_flag_weight_total": total_weight}

def gen_audit_trail(cust_id, r, alert_date, decision):
    base = alert_date
    events = [
        {"time": (base + timedelta(minutes=0)).strftime("%Y-%m-%d %H:%M"), "user": "System", "action": "Alert Generated", "comments": "Rule engine triggered alert based on transaction monitoring scenario."},
        {"time": (base + timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M"), "user": "Case Management System", "action": "Assigned", "comments": "Auto-assigned to L1 Analyst queue based on risk rating."},
        {"time": (base + timedelta(minutes=25)).strftime("%Y-%m-%d %H:%M"), "user": "L1 Analyst", "action": "KYC Reviewed", "comments": "Reviewed customer KYC/CDD documentation and identification records."},
        {"time": (base + timedelta(minutes=50)).strftime("%Y-%m-%d %H:%M"), "user": "L1 Analyst", "action": "Transaction Analysis Completed", "comments": "Reviewed 12-month transaction history against expected customer behaviour."},
        {"time": (base + timedelta(hours=1, minutes=15)).strftime("%Y-%m-%d %H:%M"), "user": "L1 Analyst", "action": "Screening Reviewed", "comments": "PEP, sanctions and adverse media screening results reviewed."},
    ]
    if decision == "Potential SAR" or decision == "Escalate to L2":
        events.append({"time": (base + timedelta(hours=1, minutes=45)).strftime("%Y-%m-%d %H:%M"), "user": "L1 Analyst", "action": "Escalated", "comments": "Case escalated to L2 Investigator based on red-flag analysis and recommendation engine output."})
    return events

def sla_status(days_open, sla_days=5):
    remaining = sla_days - days_open
    pct = min(100, round((days_open / sla_days) * 100))
    if remaining < 0:
        status = "Breached"
    elif remaining <= 1:
        status = "Near Breach"
    else:
        status = "Within SLA"
    return {"days_open": days_open, "sla_target_days": sla_days, "remaining_days": remaining,
            "progress_percent": pct, "status": status}

# ---------------------------------------------------------------- main build
output = {}
for cust_id, cust_alerts in alerts_by_cust.items():
    cust = customers[cust_id]
    r = rng_for(cust_id)
    accounts = accounts_by_cust[cust_id]
    is_corporate = any(a["account_type"] == "business" for a in accounts)
    cust_txns = txns_by_cust[cust_id]

    kyc = gen_kyc(cust, r, is_corporate)
    risk_snapshot = gen_risk_snapshot(cust, r, kyc, accounts, cust_alerts, is_corporate)
    txn_analysis = gen_transaction_analysis(cust_id, r, cust_txns, accounts)
    historical_behaviour = gen_historical_behaviour(cust, r, txn_analysis)
    aml_history = gen_aml_history(cust_id, cust, r, accounts, cust_alerts)
    pep = gen_pep(cust, r)
    sanctions = gen_sanctions(cust, r)
    osint = gen_osint(cust, r, is_corporate, pep["pep_flag"])
    ubo = gen_ubo(cust, r, is_corporate)
    red_flags = gen_red_flags(cust, r, txn_analysis, cust_alerts, is_corporate)
    recommendation = gen_recommendation(cust_alerts, red_flags, aml_history, pep, sanctions, osint)

    days_open = r.randint(0, 7)
    alert_date = TODAY - timedelta(days=days_open, hours=r.randint(0,20), minutes=r.randint(0,59))
    sla = sla_status(days_open)
    audit_trail = gen_audit_trail(cust_id, r, alert_date, recommendation["decision"])

    output[cust_id] = {
        "customer_id": cust_id,
        "accounts": [{"account_id": a["account_id"], "account_type": a["account_type"], "open_date": a["open_date"]} for a in accounts],
        "is_corporate": is_corporate,
        "kyc": kyc,
        "risk_snapshot": risk_snapshot,
        "transaction_analysis": txn_analysis,
        "historical_behaviour": historical_behaviour,
        "aml_history": aml_history,
        "pep_screening": pep,
        "sanctions_screening": sanctions,
        "osint": osint,
        "ubo": ubo,
        "red_flags": red_flags,
        "recommendation": recommendation,
        "audit_trail": audit_trail,
        "sla": sla,
        "alert_date": alert_date.strftime("%Y-%m-%d %H:%M"),
        "branch": r.choice(["Downtown Financial Centre", "Marina Bay Branch", "West End Corporate Branch",
                              "Harbourfront Retail Branch", "Central Business District Branch"]),
        "escalation_status": r.choice(["Not Escalated", "Not Escalated", "Not Escalated", "Pending L2 Review"]),
        "assigned_analyst": r.choice(["N. Fraser", "T. Wickramasinghe", "B. Odutayo", "C. Marsh", "L. Bouchard"]),
    }

with open("output/investigation_data.json", "w") as f:
    json.dump(output, f, indent=2)

print(f"Built output/investigation_data.json with investigation records for {len(output)} customers.")
