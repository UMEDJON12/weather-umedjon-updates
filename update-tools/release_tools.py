"""GitHub draft preparation and published-channel verification. No signing secrets."""
import base64,glob,hashlib,hmac,json,os,re,secrets,subprocess,tempfile,time
import urllib.request,urllib.error,urllib.parse
from pathlib import Path

REPO="UMEDJON12/weather-umedjon-updates"
PACKAGE="com.umedjon.weather"
CERT="f396b2bfc8e5dc74a03681a2abb8e1145d16b981bb97b80c095f8901d8d418d4"
API="https://api.github.com/repos/"+REPO
MAX_SIZE=80*1024*1024

def api(path,method="GET",data=None):
    headers={"Authorization":"Bearer "+os.environ["GH_TOKEN"],"Accept":"application/vnd.github+json",
             "Content-Type":"application/json","X-GitHub-Api-Version":"2022-11-28"}
    req=urllib.request.Request(API+path,method=method,headers=headers,
        data=json.dumps(data).encode() if data is not None else None)
    with urllib.request.urlopen(req,timeout=60) as r:
        body=r.read()
        return json.loads(body) if body else None

def get_file(path,ref="main"):
    try:
        obj=api("/contents/"+path+"?ref="+urllib.parse.quote(ref,safe=""))
    except urllib.error.HTTPError as e:
        if e.code==404:return None,None
        raise
    return json.loads(base64.b64decode(obj["content"])),obj["sha"]

def put_file(path,data,message):
    _,sha=get_file(path)
    body={"message":message,"branch":"main",
          "content":base64.b64encode((json.dumps(data,ensure_ascii=False,indent=2)+"\n").encode()).decode()}
    if sha:body["sha"]=sha
    api("/contents/"+path,"PUT",body)

def command(args,input=None):
    result=subprocess.run(args,input=input,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    if result.returncode:raise RuntimeError("Cryptographic or Android verification command failed")
    return result.stdout

def sdk(name):
    paths=glob.glob(os.environ.get("ANDROID_HOME","/usr/local/lib/android/sdk")+"/build-tools/*/"+name)
    assert paths,"Android SDK tool missing"
    return sorted(paths,reverse=True)[0]

class SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):
        u=urllib.parse.urlsplit(newurl)
        assert u.scheme=="https" and u.username is None and u.port in (None,443)
        assert u.hostname in ("api.github.com","github.com","release-assets.githubusercontent.com",
                              "objects.githubusercontent.com","github-releases.githubusercontent.com")
        nxt=super().redirect_request(req,fp,code,msg,headers,newurl)
        if u.hostname!=urllib.parse.urlsplit(req.full_url).hostname:nxt.remove_header("Authorization")
        return nxt

def download(asset,target,limit,authenticated=False):
    assert asset["state"]=="uploaded" and 0<asset["size"]<=limit
    url=(API+"/releases/assets/"+str(asset["id"])) if authenticated else asset["browser_download_url"]
    if not authenticated:assert url.startswith("https://github.com/"+REPO+"/releases/download/")
    headers={"User-Agent":"Weather-UMEDJON-release-verifier","Accept":"application/octet-stream"}
    if authenticated:headers["Authorization"]="Bearer "+os.environ["GH_TOKEN"]
    total=0;digest=hashlib.sha256()
    with urllib.request.build_opener(SafeRedirect()).open(urllib.request.Request(url,headers=headers),timeout=120) as r,target.open("wb") as out:
        while True:
            block=r.read(1024*1024)
            if not block:break
            total+=len(block);assert total<=limit
            out.write(block);digest.update(block)
    assert total==asset["size"]
    actual=digest.hexdigest()
    if asset.get("digest"):assert asset["digest"]=="sha256:"+actual
    return actual

def verify_metadata(data,release):
    assert data["schemaVersion"]==1 and data["applicationId"]==PACKAGE
    assert data["signingCertificateSha256"]==CERT and data["testOnly"] is False
    assert re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+",data["versionName"])
    assert data["versionCode"]>0 and data["minSdk"]==24
    assert release["tag_name"]=="v"+data["versionName"]==data["tagName"]
    assert 0<data["sizeBytes"]<=MAX_SIZE and re.fullmatch("[a-f0-9]{64}",data["sha256"])
    filename="Weather-UMEDJON-v"+data["versionName"]+".apk"
    assert data["apkUrl"]=="https://github.com/"+REPO+"/releases/download/"+data["tagName"]+"/"+filename
    assert len(data["releaseNotes"])<=8000
    return filename

def verify_release(release,authenticated=False):
    assets={a["name"]:a for a in release["assets"]}
    with tempfile.TemporaryDirectory(prefix="weather-verification-") as td:
        root=Path(td);meta=root/"update.json"
        download(assets["update.json"],meta,65536,authenticated)
        data=json.loads(meta.read_text())
        filename=verify_metadata(data,release)
        asset=assets[filename];assert asset["size"]==data["sizeBytes"]
        apk=root/filename
        assert download(asset,apk,MAX_SIZE,authenticated)==data["sha256"]
        signature=command([sdk("apksigner"),"verify","--min-sdk-version","24","--print-certs",str(apk)]).decode()
        assert re.findall(r"certificate SHA-256 digest: ([a-fA-F0-9]+)",signature)==[CERT]
        badge=command([sdk("aapt"),"dump","badging",str(apk)]).decode()
        m=re.search(r"package: name='([^']+)' versionCode='([0-9]+)' versionName='([^']+)'",badge)
        assert m and (m.group(1),int(m.group(2)),m.group(3))==(PACKAGE,data["versionCode"],data["versionName"])
        assert "sdkVersion:'24'" in badge and "testOnly" not in badge
    return data

def publish():
    event=json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    release=event.get("release") or api("/releases/latest")
    if release["draft"] or release["prerelease"]:return
    release=api("/releases/"+str(release["id"]))
    assert not release["draft"] and not release["prerelease"] and release["published_at"]
    if api("/releases/latest")["id"]!=release["id"]:return
    data=verify_release(release)
    previous,_=get_file("updates/stable.json")
    if previous and previous.get("ready"):
        assert data["versionCode"]>=previous["versionCode"]
        if data["versionCode"]==previous["versionCode"]:assert data["sha256"]==previous["sha256"]
    assert api("/releases/latest")["id"]==release["id"]
    data.update(ready=True,draft=False,prerelease=False,releaseId=release["id"],publishedAt=release["published_at"])
    put_file("updates/stable.json",data,"Publish verified Weather UMEDJON "+data["versionName"])
    print("Verified stable channel updated for",data["versionName"],flush=True)

def draft():
    request,_=get_file("checks/upload-request.json",os.environ["GITHUB_SHA"])
    assert request["repository"]==REPO and request["applicationId"]==PACKAGE and request["certificate"]==CERT
    assert re.fullmatch("[a-f0-9]{24}",request["requestId"])
    assert re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+",request["tag"])
    assert hashlib.sha256(request["publicKeyPem"].encode()).hexdigest()==request["publicKeySha256"]
    releases=api("/releases?per_page=100")
    release=next((r for r in releases if r["tag_name"]==request["tag"]),None)
    if release is None:
        release=api("/releases","POST",{"tag_name":request["tag"],"target_commitish":"main",
            "name":"Погода UMEDJON "+request["tag"][1:],"body":request["notes"],"draft":True,"prerelease":False})
    assert release["draft"] and not release["prerelease"]
    token=os.environ["GH_TOKEN"].encode()
    keys=secrets.token_bytes(64);iv=secrets.token_bytes(16)
    encrypted=command(["openssl","enc","-aes-256-cbc","-K",keys[:32].hex(),"-iv",iv.hex()],token)
    with tempfile.TemporaryDirectory() as td:
        pub=Path(td)/"public.pem";pub.write_text(request["publicKeyPem"])
        wrapped=command(["openssl","pkeyutl","-encrypt","-pubin","-inkey",str(pub),
            "-pkeyopt","rsa_padding_mode:oaep","-pkeyopt","rsa_oaep_md:sha256","-pkeyopt","rsa_mgf1_md:sha256"],keys)
    context=b"Weather scoped upload v1\0"+request["requestId"].encode()+b"\0"+REPO.encode()+b"\0"
    mac=hmac.new(keys[32:],context+iv+encrypted,hashlib.sha256).hexdigest()
    session={"requestId":request["requestId"],"runId":os.environ["GITHUB_RUN_ID"],"releaseId":release["id"],
        "encryptedToken":base64.b64encode(encrypted).decode(),"wrappedKeys":base64.b64encode(wrapped).decode(),
        "iv":iv.hex(),"hmac":mac,"draftUrl":release["html_url"]}
    put_file("checks/upload-session.json",session,"Open encrypted temporary draft upload session")
    try:
        deadline=time.monotonic()+900
        while time.monotonic()<deadline:
            result,_=get_file("checks/upload-client-result.json")
            if result and result.get("requestId")==request["requestId"]:break
            time.sleep(5)
        else:raise RuntimeError("Upload session expired")
        release=api("/releases/"+str(release["id"]));assert release["draft"]
        data=verify_release(release,True)
        assert data["sha256"]==request["sha256"] and data["versionCode"]==request["versionCode"]
        put_file("checks/draft-result.json",{"ready":True,"published":False,"releaseId":release["id"],
            "url":release["html_url"],"versionCode":data["versionCode"],"sha256":data["sha256"],
            "requestId":request["requestId"]},"Record verified draft APK and metadata")
        print("Draft assets verified. Publication is reserved for the owner.",flush=True)
    finally:
        active,sha=get_file("checks/upload-session.json")
        if active and active.get("requestId")==request["requestId"]:
            api("/contents/checks/upload-session.json","DELETE",{"message":"Close temporary draft session","sha":sha,"branch":"main"})

if __name__=="__main__":
    assert os.environ["GITHUB_REPOSITORY"]==REPO
    os.umask(0o077)
    {"publish":publish,"draft":draft}[__import__("sys").argv[1]]()
