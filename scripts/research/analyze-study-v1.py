#!/usr/bin/env python3
import argparse,csv,hashlib,json
from collections import Counter
from pathlib import Path

def j(p): return json.loads(Path(p).read_text())
def pct(a,b): return round(100*a/b,3) if b else None
def vt(s):
    p=s.split("-",1)[0].split(".")
    return int(p[0]),int(p[1])
def outcome(rows):
    c=Counter(r["verdict"] for r in rows)
    return {"attempts":len(rows),"compatible":c["compatible"],"incompatible":c["incompatible"],"inconclusive":c["inconclusive"],"evaluable":c["compatible"]+c["incompatible"]}
def csvw(p,rows,fields):
    with Path(p).open("w",newline="") as f:
        w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows(rows)

ap=argparse.ArgumentParser()
ap.add_argument("--data-dir",default="research/data/v1")
ap.add_argument("--plan",default="research/analysis/v1/analysis-plan.json")
ap.add_argument("--out-dir",default="research/analysis/v1/generated")
a=ap.parse_args();data,od=Path(a.data_dir),Path(a.out_dir);od.mkdir(parents=True,exist_ok=True)
plan=j(a.plan);summary=j(data/"processed/collection-summary.json");env=j(data/"processed/exact-environments.json");manifest=j(data/"dataset-manifest.json")
order=list(plan["case_roles"]);rows=[];h=hashlib.sha256()
for case in order:
    b=(data/"processed/executions"/f"{case}.jsonl").read_bytes();h.update(b)
    rs=[json.loads(x) for x in b.decode().splitlines() if x.strip()]
    if any(r["case_id"]!=case for r in rs): raise SystemExit("cross-case shard")
    rows+=rs
if "sha256:"+h.hexdigest()!=manifest["processed"]["canonical_executions_jsonl_sha256"]: raise SystemExit("execution digest mismatch")
raw={x["case_id"]:x["sha256"] for x in j(data/"raw-report-checksums.json")["reports"]}
if not summary["collection_complete"] or len(rows)!=70 or len({(r["case_id"],r["logical_profile_id"]) for r in rows})!=70: raise SystemExit("collection integrity failure")
if any(raw.get(r["case_id"])!=r["raw_report_sha256"] for r in rows): raise SystemExit("raw checksum mismatch")
if summary["github_run_id"]!=plan["canonical_run_id"] or summary["github_sha"]!=plan["canonical_run_sha"]: raise SystemExit("run mismatch")

roles=plan["case_roles"];overall=outcome(rows)
ct=[]
for case in sorted(order):
    o=outcome([r for r in rows if r["case_id"]==case]);ct.append({"case_id":case,"analysis_role":roles[case],**o,"incompatible_rate_evaluable_pct":pct(o["incompatible"],o["evaluable"])})
csvw(od/"case-outcomes.csv",ct,list(ct[0]))

noncal=[r for r in rows if roles[r["case_id"]]!="calibration"];noncal_o=outcome(noncal)
scopes={"all":rows,"non_calibration":noncal,"primary_real_world":[r for r in rows if roles[r["case_id"]]=="primary_real_world"],"primary_oss_derived":[r for r in rows if roles[r["case_id"]]=="primary_oss_derived"],"controlled_probe":[r for r in rows if roles[r["case_id"]]=="controlled_probe"],"calibration":[r for r in rows if roles[r["case_id"]]=="calibration"]}
tax={};tr=[]
for name,rs in scopes.items():
    o=outcome(rs);c=Counter((r.get("classification_code") or "unknown") for r in rs if r["verdict"]=="incompatible");tax[name]={**o,"taxonomy":dict(sorted(c.items()))}
    for code,n in sorted(c.items()): tr.append({"scope":name,"classification_code":code,"count":n,"evaluable_denominator":o["evaluable"],"rate_evaluable_pct":pct(n,o["evaluable"])})
csvw(od/"failure-taxonomy.csv",tr,["scope","classification_code","count","evaluable_denominator","rate_evaluable_pct"])

cfg=plan["rq1"];thr=vt(cfg["upstream_introduction_version"]);r1=[];tp=tn=fp=fn=0
for r in [x for x in rows if x["case_id"]==cfg["case_id"]]:
    s=vt(r["observed_kernel_release"]);pred="compatible" if s>=thr else "incompatible";con=r["verdict"]!="inconclusive";agree=con and pred==r["verdict"]
    if con:
        tp+=int(pred=="compatible" and r["verdict"]=="compatible");tn+=int(pred=="incompatible" and r["verdict"]=="incompatible");fp+=int(pred=="compatible" and r["verdict"]=="incompatible");fn+=int(pred=="incompatible" and r["verdict"]=="compatible")
    r1.append({"logical_profile_id":r["logical_profile_id"],"observed_kernel_release":r["observed_kernel_release"],"observed_series":f"{s[0]}.{s[1]}","version_prediction":pred,"observed_verdict":r["verdict"],"conclusive":str(con).lower(),"agreement":str(agree).lower() if con else "","classification_code":r.get("classification_code") or ""})
r1.sort(key=lambda x:(vt(x["observed_series"]),x["logical_profile_id"]));csvw(od/"rq1-ringbuf-version.csv",r1,list(r1[0]))
ev=tp+tn+fp+fn
rq1={"feature":cfg["feature"],"upstream_introduction_version":cfg["upstream_introduction_version"],"upstream_commit":cfg["upstream_commit"],"evaluable":ev,"agreement":tp+tn,"disagreement":fp+fn,"agreement_pct":pct(tp+tn,ev),"true_positive":tp,"true_negative":tn,"false_positive":fp,"false_negative":fn,"sensitivity_pct":pct(tp,tp+fn),"specificity_pct":pct(tn,tn+fp),"below_threshold_compatible_profiles":[x["logical_profile_id"] for x in r1 if x["conclusive"]=="true" and x["version_prediction"]=="incompatible" and x["observed_verdict"]=="compatible"]}

idx={(r["case_id"],r["logical_profile_id"]):r for r in rows};q3=plan["rq3"];pairs=[];dis=conc=0;matrix=Counter()
for pid in sorted({r["logical_profile_id"] for r in rows if r["case_id"]==q3["left_case"]}):
    l=idx[(q3["left_case"],pid)];rr=idx[(q3["right_case"],pid)];bc=l["verdict"]!="inconclusive" and rr["verdict"]!="inconclusive";conc+=int(bc);dis+=int(bc and l["verdict"]!=rr["verdict"]);matrix[(l["verdict"],rr["verdict"])]+=1
    pairs.append({"logical_profile_id":pid,"environment_id":l["environment_id"],"same_exact_environment":str(l["environment_id"]==rr["environment_id"]).lower(),"left_verdict":l["verdict"],"right_verdict":rr["verdict"],"both_conclusive":str(bc).lower(),"verdict_disagreement":str(bc and l["verdict"]!=rr["verdict"]).lower(),"contracts_comparable":"false"})
csvw(od/"rq3-loader-pairs.csv",pairs,list(pairs[0]))
rq3={"conclusive_pairs":conc,"verdict_disagreements":dis,"verdict_disagreement_pct":pct(dis,conc),"contracts_comparable":False,"verdict_matrix":{f"{x}__{y}":n for (x,y),n in sorted(matrix.items())},"interpretation_constraint":q3["reason"]}

er=[{"logical_profile_id":e["logical_profile_id"],"distribution":e["distribution"],"distribution_release":e["distribution_release"],"requested_kernel_family":e["requested_kernel_family"],"observed_kernel_release":e["observed_kernel_release"],"kernel_family_match":str(e["kernel_family_match"]).lower(),"exact_environment_id":e["exact_environment_id"],"image_identity":e["image_identity"]} for e in sorted(env["environments"],key=lambda x:x["logical_profile_id"])]
csvw(od/"rq4-environments.csv",er,list(er[0]));inv=[]
for case in order:
    rs=[r for r in rows if r["case_id"]==case and r["verdict"]!="inconclusive"]
    for x in rs:
        for y in rs:
            if vt(x["observed_kernel_release"])<vt(y["observed_kernel_release"]) and x["verdict"]=="compatible" and y["verdict"]=="incompatible": inv.append({"case_id":case,"analysis_role":roles[case],"older_profile":x["logical_profile_id"],"older_kernel":x["observed_kernel_release"],"newer_profile":y["logical_profile_id"],"newer_kernel":y["observed_kernel_release"]})
csvw(od/"rq4-version-inversions.csv",inv,["case_id","analysis_role","older_profile","older_kernel","newer_profile","newer_kernel"])
rq4={"logical_profiles":10,"exact_environments":len(env["environments"]),"patch_level_longitudinal_evaluable":False,"cross_vendor_version_inversions":len(inv),"ringbuf_below_upstream_threshold_compatible_profiles":rq1["below_threshold_compatible_profiles"]}

limitations=["Selected stratified x86_64 pilot; not representative of global Linux deployments.","Controlled probes and calibration are not mixed into real-world prevalence claims.","Cilium paths use load+attach versus load-only, so agreement is not a pure loader-effect estimate.","Oracle requested 5.15 but booted 6.12 UEK; seven executions are inconclusive for the requested profile.","One exact environment per logical profile prevents patch-level longitudinal inference."]
result={"schema_version":"bpfcompat.research.analysis-summary.v1","corpus_version":"v1","canonical_run_id":plan["canonical_run_id"],"canonical_run_sha":plan["canonical_run_sha"],"collection_complete":True,"fully_evaluable":summary["fully_evaluable"],"overall":overall,"non_calibration":noncal_o,"rq1_version_predictiveness":rq1,"rq2_failure_taxonomy":tax,"rq3_loader_pair_observations":[rq3],"rq4_vendor_and_environment_variation":rq4,"limitations":limitations}
(od/"analysis-summary.json").write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
lines=["# Pilot v1 generated results","", "This file is generated from the canonical v1 dataset; it is descriptive pilot analysis, not a population estimate.","", "## Collection","",f"- 70/70 execution records collected.",f"- Overall: {overall['compatible']} compatible, {overall['incompatible']} incompatible, {overall['inconclusive']} inconclusive.",f"- Non-calibration: {noncal_o['compatible']} compatible, {noncal_o['incompatible']} incompatible, {noncal_o['inconclusive']} inconclusive.","","## RQ1 — kernel-version predictiveness","",f"For the controlled BPF_MAP_TYPE_RINGBUF probe, a simple Linux 5.8 threshold agreed with {rq1['agreement']}/{rq1['evaluable']} conclusive observations ({rq1['agreement_pct']}%). The exception was {', '.join(rq1['below_threshold_compatible_profiles'])}, whose observed 4.18 vendor kernel supported the probe.","","## RQ2 — failure taxonomy","",f"Outside calibration there were {tax['non_calibration']['incompatible']} incompatible observations among {tax['non_calibration']['evaluable']} evaluable executions: "+", ".join(f"{k} = {v}" for k,v in tax['non_calibration']['taxonomy'].items())+".","","## RQ3 — loader-path observation","",f"The paired Cilium-derived paths had {rq3['verdict_disagreements']} verdict disagreements across {rq3['conclusive_pairs']} conclusive environments. The contracts differ (load+attach vs load-only), so this is not a pure loader-effect estimate.","","## RQ4 — vendor/environment variation","",f"The dataset contains {rq4['exact_environments']} exact environments across 10 logical profiles and {rq4['cross_vendor_version_inversions']} cross-vendor version inversions. Patch-level longitudinal change is not evaluable in v1.","","## Limitations",""]+[f"- {x}" for x in limitations]
(od/"RESULTS.md").write_text("\n".join(lines)+"\n")
