const { chromium } = require("playwright-core");
const EXE = "C:/Users/User/AppData/Local/ms-playwright/chromium-1187/chrome-win/chrome.exe";
const OUT = "C:/Users/User/AppData/Local/Temp/claude/D--/9f23cb05-21bf-4b04-9492-fda0f452d63c/scratchpad/ovru";

async function gen(page, withImage, file){
  // select branded template
  await page.evaluate(async () => {
    const sel = document.getElementById("tmplSel");
    for (let i=0;i<60 && !sel.options.length;i++){ await new Promise(r=>setTimeout(r,150)); }
    sel.value = "kravchenko_thorax"; sel.dispatchEvent(new Event("change"));
    await new Promise(r=>setTimeout(r,1200));
  });
  if (withImage){
    await page.evaluate(async () => {
      const cv=document.createElement("canvas"); cv.width=300; cv.height=430;
      const cx=cv.getContext("2d"); cx.fillStyle="#222"; cx.fillRect(0,0,300,430);
      cx.fillStyle="#ccc"; cx.font="34px sans-serif"; cx.fillText("X-RAY", 85, 220);
      const blob=await new Promise(r=>cv.toBlob(r,"image/png"));
      const f=new File([blob],"x.png",{type:"image/png"});
      const dt=new DataTransfer(); dt.items.add(f);
      const inp=document.getElementById("imgFile"); inp.files=dt.files; inp.dispatchEvent(new Event("change"));
      await new Promise(r=>setTimeout(r,600));
    });
  }
  // trigger branded print path (populates #printArea + body.pbrand + @page), then capture via page.pdf
  await page.evaluate(() => document.getElementById("pdfBtn").click());
  await page.waitForTimeout(500);
  await page.pdf({ path: OUT + "/" + file, printBackground: true, format: "A4", margin: { top:"0", right:"0", bottom:"0", left:"0" } });
  // reset for next
  await page.evaluate(() => { document.body.classList.remove("pbrand"); const pa=document.getElementById("printArea"); if(pa) pa.innerHTML=""; const s=document.getElementById("pbrandpage"); if(s) s.remove(); });
  console.log("wrote", file);
}

(async () => {
  const browser = await chromium.launch({ executablePath: EXE });
  const ctx = await browser.newContext({ httpCredentials: { username: "demo", password: "demo" } });
  const page = await ctx.newPage();
  await page.goto("https://scriber.akesosystems.com/", { waitUntil: "networkidle" });
  await gen(page, false, "pdf_norm.pdf");
  await page.reload({ waitUntil: "networkidle" });
  await gen(page, true, "pdf_image.pdf");
  await browser.close();
  console.log("done");
})().catch(e => { console.error("ERR", e.message); process.exit(1); });
