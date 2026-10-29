"""
گشت خودکار کل رابط در حالت انگلیسی؛ هر متن فارسیِ ترجمه‌نشده را در dev/_untranslated.json گزارش می‌کند.
پیش‌نیاز: sh dev/fresh_harness.sh (harness تازه روی 8765)، Playwright، و برای بخش SSH: sshd آزمایشی روی 2222 و
python dev/fake_cisco.py 2223. اجرا: python dev/ui_crawl_en.py [مسیر یک ipabuse_report.csv نمونه]
"""
import asyncio, json, sys
IMPORT_CSV = sys.argv[1] if len(sys.argv) > 1 else "dev/sample_ipabuse_report.csv"
from playwright.async_api import async_playwright
COLLECT = """() => {
  const FA=/[\\u0600-\\u06FF]/, out=new Set();
  const skip=(e)=>{for(;e&&e.nodeType===1;e=e.parentElement){if(['SCRIPT','STYLE','TEXTAREA','INPUT','CODE'].includes(e.tagName)||e.hasAttribute('data-no-i18n'))return true;
     const cs=getComputedStyle(e); if(cs.display==='none'||cs.visibility==='hidden')return true; if(e.hidden)return true;} return false;};
  const skipA=(e)=>{for(let x=e;x&&x.nodeType===1;x=x.parentElement){if(x.hasAttribute('data-no-i18n'))return true; const cs=getComputedStyle(x); if(cs.display==='none'||x.hidden)return true;} return false;};
  const tw=document.createTreeWalker(document.body,NodeFilter.SHOW_TEXT|NodeFilter.SHOW_ELEMENT);
  for(let n=tw.nextNode();n;n=tw.nextNode()){
    if(n.nodeType===3){ if(FA.test(n.nodeValue)&&!skip(n.parentElement)) out.add(n.nodeValue.trim()); }
    else for(const a of ['title','placeholder']){const v=n.getAttribute(a); if(v&&FA.test(v)&&!skipA(n)) out.add('@'+a+': '+v);}
  }
  return [...out];
}"""
async def main():
    found = {}
    async with async_playwright() as p:
        b = await p.chromium.launch(); pg = await b.new_page(viewport={"width":1400,"height":900}); pg.set_default_timeout(20000); errs=[]
        pg.on("pageerror", lambda e: errs.append(str(e) + " @ " + (e.stack or "")[:300])); pg.on("console", lambda m: errs.append(m.text) if m.type=="error" else None)
        async def grab(tag):
            await pg.wait_for_timeout(450)
            for s in await pg.evaluate(COLLECT): found.setdefault(s, tag)
        async def api(name, *args): return await pg.evaluate(f"(a)=>window.pywebview.api.{name}(...a)", list(args))
        await pg.goto("http://127.0.0.1:8765/"); await pg.wait_for_timeout(1200)
        await pg.click(".lang-toggle"); await pg.wait_for_timeout(600); await grab("lock-setup")
        for m in ("password",): await pg.click(f".mode-card[data-m={m}]"); await grab("lock-"+m)
        await pg.click(".mode-card[data-m=simple]"); await pg.click("#lsGo"); await pg.wait_for_timeout(1500)
        # data
        await api("import_commit", IMPORT_CSV, False)
        await api("save_settings", {"test_mode": True})
        d1=(await api("ssh_save_device", {"name":"lx","host":"127.0.0.1","port":2222,"device_type":"linux","username":"tester","grp":"lab"}, "T3st!pass"))["id"]
        d2=(await api("ssh_save_device", {"name":"R1","host":"127.0.0.1","port":2223,"device_type":"cisco_ios","username":"admin","use_enable":1}, "C1sco!pass","En@ble"))["id"]
        await api("ssh_save_script", {"name":"uptime","device_type":"linux","body":"uptime"})
        await api("save_settings", {"backup":{"commands":{"linux":"cat /etc/hostname"}}})
        await api("ssh_set_backup", [d1], True)
        await grab("dashboard")
        await pg.click("#nav button[data-page=run]"); await grab("run-form")
        await pg.click("#btnStart"); await pg.wait_for_selector("#apOk"); await grab("approval-fw")
        await pg.click("#apOk"); await grab("confirm-fw"); await pg.click(".m-foot [data-r='1']")
        await pg.wait_for_selector(".approval h2 >> text=Redmine"); await grab("approval-rm")
        await pg.click("#apOk"); await grab("confirm-rm"); await pg.click(".m-foot [data-r='1']"); await pg.wait_for_timeout(2000)
        for t in ["summary","mal","clean","err","fw","log"]:
            await pg.click(f"[data-rt={t}]"); await grab("result-"+t)
        await pg.click("#nav button[data-page=dashboard]"); await grab("dashboard2")
        await pg.click("#nav button[data-page=auto]")
        for t in ["daily","retry","tpl"]: await pg.click(f"#autoTabs button[data-t={t}]"); await grab("auto-"+t)
        await pg.click("#nav button[data-page=ips]"); await pg.wait_for_timeout(800); await grab("ips")
        for f in ["ABUSE","review","ERROR","unchecked","banned","fw_pending","all"]: await pg.click(f"#ipFilter button[data-f={f}]"); await grab("ips-"+f)
        await pg.click("#btnCols"); await grab("cols"); await pg.keyboard.press("Escape")
        await pg.click("#ipTable .link.ip >> nth=0"); await grab("ip-detail"); await pg.keyboard.press("Escape")
        c=await pg.query_selector_all(".ipChk"); await c[0].click(); await grab("selbar")
        for act in ["recheck","ban","reviewed","ignore"]:
            await pg.click(f"#selBar [data-act={act}]"); await grab("act-"+act); await pg.keyboard.press("Escape")
        await pg.click("#selBar [data-act=clear]")
        await pg.click("#btnAddData"); await pg.fill("#impPath",IMPORT_CSV); await pg.click("#impPrev"); await pg.wait_for_selector("#impGo"); await grab("import")
        await pg.click("[data-dt=manual]"); await grab("manual"); await pg.keyboard.press("Escape")
        await pg.click("#btnExport"); await grab("export"); await pg.keyboard.press("Escape")
        await pg.click("#btnFullSync"); await grab("fullsync"); await pg.keyboard.press("Escape")
        await pg.click("#nav button[data-page=ssh]"); await pg.wait_for_timeout(800); await grab("ssh-devices")
        await pg.click("#sshAdd"); await grab("ssh-add"); await pg.keyboard.press("Escape")
        await pg.click("#sshBulk"); await grab("ssh-bulk"); await pg.keyboard.press("Escape")
        await pg.click("#sshAll"); await grab("ssh-selbar")
        await pg.click("#sshSelBar [data-sa=backup]"); await pg.wait_for_timeout(5000); await grab("ssh-backups")
        await pg.click("#sshTabs button[data-t=devices]"); await pg.wait_for_timeout(500)
        await pg.click("#sshKeys"); await grab("ssh-keys"); await pg.keyboard.press("Escape")
        await pg.click("#sshAll"); await pg.click("#sshAll"); await pg.click("#sshSelBar [data-sa=test]"); await pg.wait_for_timeout(5000); await grab("ssh-test")
        await pg.click("#rnPick"); await grab("ssh-pick"); await pg.click("[data-g=__all]"); await pg.click("#pkOk"); await pg.wait_for_timeout(300); await grab("ssh-run")
        await pg.click("#rnScript"); await pg.select_option("#rnScript", index=1); await pg.wait_for_timeout(400); await grab("ssh-run-script")
        await pg.click("#rnSaveAs"); await grab("ssh-saveas"); await pg.keyboard.press("Escape")
        await pg.click("#rnGo"); await pg.wait_for_timeout(800); await grab("ssh-preview"); await pg.click("[data-c=dry]"); await pg.wait_for_timeout(3000); await grab("ssh-dry")
        await pg.click("#sshTabs button[data-t=backups]"); await pg.wait_for_timeout(1000); await grab("ssh-backups2")
        await pg.evaluate("document.querySelector('#page-ssh details').open = true"); await grab("ssh-bk-settings")
        btn = await pg.query_selector("[data-bv]")
        if btn: await btn.click(); await pg.wait_for_timeout(800); await grab("ssh-bk-view"); await pg.keyboard.press("Escape")
        btn = await pg.query_selector("[data-bdf]")
        if btn: await btn.click(); await grab("ssh-bk-diff"); await pg.keyboard.press("Escape")
        await pg.click("#sshTabs button[data-t=fgu]"); await pg.wait_for_timeout(900); await grab("ssh-fgu")
        await pg.click("[name=fguSrc][value=remote]"); await grab("ssh-fgu-remote")
        await pg.click("#sshTabs button[data-t=jobs]"); await pg.wait_for_timeout(600); await grab("ssh-jobs")
        await pg.click("[data-jb] >> nth=0"); await grab("ssh-job-detail"); await pg.keyboard.press("Escape")
        await pg.click("#nav button[data-page=auto]"); await pg.click("#autoTabs button[data-t=backup]"); await grab("auto-backup")
        await pg.click("#nav button[data-page=stats]"); await pg.wait_for_timeout(1500); await grab("stats")
        await pg.click("#stRange button[data-v='12m']"); await pg.wait_for_timeout(1200); await grab("stats-12m")
        await pg.click("#stCal button[data-v=jalali]"); await pg.wait_for_timeout(1200); await grab("stats-jalali")
        box=await (await pg.query_selector("#chAbuse svg")).bounding_box(); await pg.mouse.move(box["x"]+box["width"]*0.8, box["y"]+box["height"]/2, steps=4); await grab("tooltip")
        await pg.click("#nav button[data-page=history]"); await pg.wait_for_timeout(700); await grab("history")
        await pg.click("#nav button[data-page=settings]")
        for t in ["general","splunk","abuseipdb","fortigate","redmine","notify","security"]:
            await pg.click(f"#setTabs button[data-t={t}]"); await grab("set-"+t)
        await pg.click("#setTabs button[data-t=splunk]"); await pg.click("#btnSpPrev"); await grab("splunk-preview")
        await pg.click("#setTabs button[data-t=redmine]"); await pg.click("#btnDiscover"); await grab("discover"); await pg.keyboard.press("Escape")
        await pg.click("#nav button[data-page=about]"); await grab("about")
        await pg.screenshot(path="/tmp/en_about.png")
        json.dump(found, open("dev/_untranslated.json","w",encoding="utf-8"), ensure_ascii=False, indent=1)
        print("untranslated:", len(found)); print("ERR", errs[:5])
        await b.close()
asyncio.run(main())
