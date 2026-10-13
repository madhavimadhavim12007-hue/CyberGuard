const $ = id => document.getElementById(id);
const messageInput=$("messageInput"), results=$("results"), scoreValue=$("scoreValue"), scoreCircle=$("scoreCircle"), severityBadge=$("severityBadge"), summaryTitle=$("summaryTitle"), summaryText=$("summaryText"), findingsList=$("findingsList"), recommendationsList=$("recommendationsList"), urlsList=$("urlsList");
const examples={
 digital:"This is an urgent notice from the Cyber Crime Department. Your Aadhaar and bank account are involved in money laundering. You are under digital arrest. Stay on video call and do not disconnect. Transfer the security amount immediately to avoid arrest.",
 phishing:"Your bank account will be blocked today. Verify your KYC immediately by clicking https://secure-bank-login.example.com/verify and enter your OTP, password, and card details.",
 application:"Police investigation notice. Install this APK immediately and open it during the video call. Download AnyDesk and share your screen. Failure to cooperate will result in arrest."
};
const patterns=[
 {label:"Digital arrest language",re:/\bdigital arrest\b|\bunder arrest\b|\bvirtual arrest\b/i,score:30,reason:"Digital or virtual arrest language is a common impersonation scam warning sign."},
 {label:"Government or law-enforcement impersonation",re:/\bpolice\b|\bcyber crime\b|\bcybercrime\b|\bcbi\b|\bfbi\b|\bcourt\b|\bcustoms\b|\bincome tax\b|\bgovernment\b|\binterpol\b|\bdepartment\b/i,score:15,reason:"The sender may be impersonating law enforcement or a government department."},
 {label:"Urgency or threat",re:/\burgent\b|\bimmediately\b|\bwithin\s+\d+\s*(hour|hours|day|days)\b|\btoday\b|\blast warning\b|\bfinal notice\b|\baccount will be blocked\b|\bavoid arrest\b|\bface arrest\b/i,score:15,reason:"Urgent threats can pressure people into acting without checking."},
 {label:"Video-call coercion",re:/\bvideo call\b|\bstay on (the )?call\b|\bdo not disconnect\b|\bkeep your camera\b|\bdo not tell anyone\b/i,score:15,reason:"Scammers may use calls and isolation to stop independent verification."},
 {label:"Payment request",re:/\btransfer\b|\bpay\b|\bpayment\b|\bsecurity deposit\b|\bsecurity amount\b|\bfine\b|\bfee\b|\brefund\b|\bupi\b|\bwallet\b|\bwire transfer\b|\bgift card\b|\bcrypto(currency)?\b/i,score:20,reason:"Unexpected payment demands are a strong warning sign."},
 {label:"Credential or OTP request",re:/\botp\b|\bone[- ]time password\b|\bpassword\b|\bpin\b|\bcvv\b|\bcard details\b|\blogin\b|\bverify your kyc\b|\baccount details\b/i,score:20,reason:"Do not share passwords, PINs, CVVs, or OTPs through suspicious messages."},
 {label:"Remote access request",re:/\banydesk\b|\bteamviewer\b|\bquick support\b|\bremote access\b|\bscreen sharing\b|\bshare your screen\b|\binstall this app\b/i,score:25,reason:"Remote-control apps may let another person view or control your device."},
 {label:"Suspicious application download",re:/\.apk\b|\bdownload.{0,20}app\b|\binstall.{0,20}apk\b|\bunknown sources\b|\bmod apk\b/i,score:25,reason:"Installing apps from message links or unknown sources can expose your device to malware."},
 {label:"Secrecy or isolation request",re:/\bdo not tell anyone\b|\bkeep this confidential\b|\bdo not contact your bank\b|\bdo not speak to your family\b|\bdo not share\b/i,score:15,reason:"Scammers may try to stop you asking family or trusted people for help."},
 {label:"Identity or account problem",re:/\bkyc\b|\baadhaar\b|\bpan card\b|\baccount suspended\b|\baccount blocked\b|\bmoney laundering\b|\billegal transaction\b|\bverification failed\b/i,score:12,reason:"Fake KYC and account-problem claims are often used in phishing messages."}
];
const shorteners=["bit.ly","tinyurl.com","t.co","goo.gl","is.gd","ow.ly","buff.ly","cutt.ly"];
const riskyTlds=["xyz","top","click","work","zip","country","gq","tk","ml","ga","cf"];
function extractUrls(text){return [...new Set(text.match(/\b(?:(?:https?:\/\/|www\.)[^\s<>"']+|(?:[a-z0-9-]+\.)+(?:com|net|org|info|biz|xyz|top|site|app|online|co|in|us|zip)\b[^\s<>"']*)/gi)||[])].map(u=>u.replace(/[),.;!?]+$/g,""))}
function analyzeUrl(raw){
 let normalized=raw;if(normalized.startsWith("www."))normalized="https://"+normalized;else if(!/^https?:\/\//i.test(normalized))normalized="https://"+normalized;
 let parsed;try{parsed=new URL(normalized)}catch{return {score:15,findings:["The detected link has an invalid or unusual URL format."]}}
 const host=parsed.hostname.toLowerCase(), findings=[];let score=0;
 const add=(points,msg)=>{score+=points;findings.push(msg)};
 if(parsed.protocol!=="https:")add(8,"The link does not use HTTPS.");
 if(/^\d{1,3}(\.\d{1,3}){3}$/.test(host))add(25,"The link uses a raw IP address instead of a normal domain name.");
 if(host.includes("xn--"))add(25,"The domain uses punycode, which can hide look-alike characters.");
 if(parsed.username||parsed.password||normalized.includes("@"))add(25,"The URL contains an @ symbol or embedded login information.");
 if(host.split(".").length>=5)add(12,"The domain contains an unusually large number of subdomains.");
 if(host.length>45)add(10,"The domain name is unusually long and may be deceptive.");
 if((host.match(/-/g)||[]).length>=3)add(8,"The domain contains many hyphens.");
 if(shorteners.some(d=>host===d||host.endsWith("."+d)))add(18,"The link uses a URL-shortening service, hiding the final destination.");
 if(riskyTlds.includes(host.split(".").pop()))add(15,"The link uses a domain extension that can be abused.");
 if(["paypa1","g00gle","micros0ft","faceb00k","amaz0n","whatsapp-security","bank-login","secure-verification"].some(s=>host.includes(s)))add(20,"The domain contains possible brand-impersonation terms.");
 return {score:Math.min(score,60),findings};
}
function severity(score){
 if(score>=75)return ["Critical Risk","critical","Highly suspicious content detected","Do not respond, click links, transfer money, or install applications."];
 if(score>=50)return ["High Risk","high","Multiple scam indicators detected","Treat this content as potentially malicious and verify it independently."];
 if(score>=30)return ["Medium Risk","medium","Some suspicious indicators detected","Be cautious and verify the sender through an official channel."];
 if(score>=15)return ["Low Risk","low","A few warning signs detected","This content is not automatically safe; verify it before acting."];
 return ["Minimal Risk","safe","No major known warning signs detected","This heuristic check does not prove the content is safe."];
}
function analyzeContent(text){
 let score=0;const findings=[],urls=extractUrls(text);
 for(const p of patterns)if(p.re.test(text)){score+=p.score;findings.push({label:p.label,reason:p.reason,score:p.score})}
 for(const url of urls){const result=analyzeUrl(url);score+=result.score;result.findings.forEach(reason=>findings.push({label:"Suspicious URL characteristic",reason,score:result.score}))}
 return {score:Math.min(Math.round(score),100),findings,urls};
}
function render(a){
 const s=severity(a.score);results.classList.add("visible");scoreValue.textContent=a.score;
 const color=a.score>=75?"#dc2626":a.score>=50?"#ea580c":a.score>=30?"#d97706":"#16a34a";
 const deg=a.score*3.6;scoreCircle.style.background=`conic-gradient(${color} ${deg}deg,#e5e7eb ${deg}deg)`;
 severityBadge.textContent=s[0];severityBadge.className="severity "+s[1];summaryTitle.textContent=s[2];summaryText.textContent=s[3];
 findingsList.replaceChildren();
 if(!a.findings.length){const p=document.createElement("p");p.className="empty";p.textContent="No known warning patterns were detected.";findingsList.append(p)}
 a.findings.forEach(f=>{const div=document.createElement("div");div.className="finding";const strong=document.createElement("strong");strong.textContent=`${f.label} (+${f.score})`;const span=document.createElement("span");span.textContent=f.reason;div.append(strong,span);findingsList.append(div)});
 const rec=["Do not click suspicious links or download unknown attachments.","Never share OTPs, passwords, PINs, CVVs, or banking information.","Verify the message through the organisation's official website or phone number.","If money or credentials were shared, contact your bank and India's cybercrime helpline 1930 promptly."];
 if(a.findings.some(f=>f.label==="Digital arrest language"))rec.unshift("Do not pay money to cancel an alleged arrest. Verify independently with official authorities.");
 if(a.findings.some(f=>f.label==="Remote access request"))rec.unshift("Do not install AnyDesk, TeamViewer, or remote-control apps at an unknown person's request.");
 if(a.findings.some(f=>f.label==="Suspicious application download"))rec.unshift("Avoid installing APK files received through SMS, WhatsApp, email, or social media.");
 if(a.urls.length)rec.unshift("Do not open the detected URL until independently verified.");
 recommendationsList.replaceChildren();[...new Set(rec)].forEach(t=>{const li=document.createElement("li");li.textContent=t;recommendationsList.append(li)});
 urlsList.replaceChildren();if(!a.urls.length){const p=document.createElement("p");p.className="empty";p.textContent="No URL detected in the submitted content.";urlsList.append(p)}
 a.urls.forEach(u=>{const d=document.createElement("div");d.className="url-item";d.textContent=u;urlsList.append(d)});
 results.scrollIntoView({behavior:"smooth",block:"start"});
}
$("analyzeBtn").addEventListener("click",()=>{const text=messageInput.value.trim();if(!text){alert("Please paste a suspicious message or link first.");return}render(analyzeContent(text))});
$("clearBtn").addEventListener("click",()=>{messageInput.value="";results.classList.remove("visible");messageInput.focus()});
document.querySelectorAll(".example-btn").forEach(b=>b.addEventListener("click",()=>{messageInput.value=examples[b.dataset.example]||"";messageInput.focus()}));
