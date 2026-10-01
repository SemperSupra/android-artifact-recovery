#!/usr/bin/env python3
from __future__ import annotations
import argparse, collections, json, pathlib, re
from urllib.parse import urlparse

KEYWORDS = [
    'voice','audio','speech','realtime','webrtc','websocket','camera','photo','image','upload',
    'file','attachment','screen','accessibility','capture','search','browse','browser','connector',
    'plugin','memory','project','task','notification','share','widget','auth','oauth','pkce',
    'device_code','devicecode','login','codex','canvas','conversation','history','model','tool',
    'location','bluetooth'
]
LIBRARY_MARKERS = {
    'okhttp':'okhttp3/', 'retrofit':'retrofit2/', 'grpc':'io/grpc/', 'webrtc':'org/webrtc/',
    'react-native':'com/facebook/react/', 'expo':'expo/modules/', 'kotlinx':'kotlinx/',
    'compose':'androidx/compose/', 'room':'androidx/room/', 'datadog':'com/datadog/',
    'sentry':'io/sentry/', 'firebase':'com/google/firebase/', 'auth0':'com/auth0/',
    'appauth':'net/openid/appauth/', 'ktor':'io/ktor/'
}
PROTOCOL_MARKERS = {
    'siwc_plan_scope': ['chatgpt.tokens.use.direct'],
    'siwc_dynamic_client': ['dynamic_agent_client'],
    'siwc_host_id': ['ext_agent_host_id'],
    'pkce_code_challenge': ['code_challenge'],
    'oauth_device_code': ['device_code', 'devicecode'],
    'siwc_authorize_endpoint': ['auth.openai.com/api/accounts/authorize'],
    'siwc_token_endpoint': ['auth.openai.com/api/accounts/oauth/token'],
    'responses_api_path': ['/v1/responses'],
    'openai_auth_host': ['auth.openai.com'],
    'android_chat_host': ['android.chat.openai.com'],
    'chatgpt_web_host': ['chatgpt.com'],
    'api_openai_host': ['api.openai.com'],
    'webrtc_surface': ['org/webrtc/', 'webrtc'],
    'media_projection': ['mediaprojection', 'media_projection'],
    'screen_share': ['screenshare', 'screen_share', 'screen share'],
    'camera_surface': ['camera2', 'cameraaccess', 'android.hardware.camera'],
    'share_intent': ['action_send', 'intent.action_send'],
    'push_messaging': ['firebasemessagingservice', 'firebase messaging'],
    'codex_handoff': ['codexchatgpthandoff', 'codex_chatgpt_handoff'],
    'realtime_voice': ['realtimevoice', 'realtime_voice'],
    'conversation_bubble': ['conversationbubble', 'conversation_bubble'],
    'temporary_chat': ['temporarychat', 'temporary_chat'],
    'file_library': ['filelibrary', 'file_library'],
    'connector_auth': ['connectorauth', 'connector_auth'],
}
URL_RE = re.compile(r'https?://[^\s"\'<>\\)]+', re.I)
HOSTISH_RE = re.compile(r'(?<![A-Za-z0-9_-])(?:[A-Za-z0-9-]+\\.)+(?:com|net|org|io|ai|dev|app)(?![A-Za-z0-9_-])', re.I)
PERMISSION_RE = re.compile(r'android\.permission\.[A-Z0-9_]+')
AAPT_COMPONENT_RE = re.compile(r'^\s*E:\s+(activity|activity-alias|service|receiver|provider)\b', re.M)
AAPT_NAME_RE = re.compile(r'android:name[^=]*="([^"]+)"')

def read_text(path: pathlib.Path) -> str:
    try: return path.read_text(encoding='utf-8', errors='ignore')
    except OSError: return ''

def parse_manifest(text: str, permissions_text: str) -> dict:
    perms=sorted(set(PERMISSION_RE.findall(text + '\n' + permissions_text)))
    xml_counts=collections.Counter(re.findall(r'<(activity|activity-alias|service|receiver|provider)\b', text))
    aapt_counts=collections.Counter(AAPT_COMPONENT_RE.findall(text))
    counts=xml_counts or aapt_counts
    exported=[]
    for block in re.findall(r'<(?:activity|activity-alias|service|receiver|provider)\b[^>]*>', text):
        if 'android:exported="true"' in block:
            name=re.search(r'android:name="([^"]+)"', block)
            if name and len(exported)<100: exported.append(name.group(1))
    if not exported and 'E: ' in text:
        lines=text.splitlines()
        for i,line in enumerate(lines):
            if not AAPT_COMPONENT_RE.search(line): continue
            block='\n'.join(lines[i:i+12])
            if 'android:exported' in block and ('0xffffffff' in block or 'true' in block.lower()):
                name=AAPT_NAME_RE.search(block)
                if name and len(exported)<100: exported.append(name.group(1))
    return {'permissions':perms,'component_counts':dict(counts),'exported_component_names':sorted(set(exported))}

def main() -> int:
    p=argparse.ArgumentParser()
    p.add_argument('--jadx-root', required=True); p.add_argument('--manifest', required=True)
    p.add_argument('--permissions'); p.add_argument('--out', required=True); p.add_argument('--max-files', type=int, default=60000)
    args=p.parse_args()
    root=pathlib.Path(args.jadx_root); files=[x for x in root.rglob('*') if x.is_file()][:args.max_files]
    keyword_hits=collections.Counter(); library_hits={k:0 for k in LIBRARY_MARKERS}; hosts=collections.Counter()
    named_paths=[]; ext_counts=collections.Counter(); marker_files={k:[] for k in PROTOCOL_MARKERS}
    for path in files:
        rel=path.relative_to(root).as_posix(); rel_l=rel.lower(); ext_counts[path.suffix.lower() or '<none>'] += 1
        for name,marker in LIBRARY_MARKERS.items():
            if marker in rel_l: library_hits[name]+=1
        text=read_text(path); low=text.lower(); combined=rel_l+'\n'+low
        for kw in KEYWORDS:
            if kw in combined: keyword_hits[kw]+=1
        for name,patterns in PROTOCOL_MARKERS.items():
            if any(pattern in combined for pattern in patterns): marker_files[name].append(rel)
        for m in URL_RE.finditer(text):
            try: h=urlparse(m.group(0)).hostname
            except ValueError: h=None
            if h: hosts[h.lower().strip('.')]+=1
        for m in HOSTISH_RE.finditer(text): hosts[m.group(0).lower().strip('.')]+=1
        if any(k in rel_l for k in ('openai','chatgpt','voice','realtime','auth','oauth','accessibility','screen','image','camera','conversation','codex')):
            if len(named_paths)<300 and len(path.stem)<160: named_paths.append(rel)
    manifest=read_text(pathlib.Path(args.manifest)); permissions_text=read_text(pathlib.Path(args.permissions)) if args.permissions else ''
    openai_hosts=[h for h,c in hosts.most_common() if any(s in h for s in ('openai','chatgpt','oaistatic'))][:100]
    other_hosts=[h for h,c in hosts.most_common() if h not in openai_hosts][:100]
    protocol={name:{'file_count':len(paths),'sample_paths':sorted(set(paths))[:20]} for name,paths in marker_files.items() if paths}
    doc={
      'schema':'aar-derived-android-surface/v1','files_scanned':len(files),'extensions':dict(ext_counts.most_common()),
      'feature_markers':{k:keyword_hits[k] for k in KEYWORDS if keyword_hits[k]},
      'library_markers':{k:v for k,v in library_hits.items() if v}, 'protocol_markers':protocol,
      'network_hosts':{'openai_related':openai_hosts,'other_observed':other_hosts},
      'manifest':parse_manifest(manifest,permissions_text), 'interesting_paths':sorted(set(named_paths))[:300],
      'limits':{'max_files':args.max_files,'max_interesting_paths':300,'max_hosts_each':100,'max_protocol_sample_paths':20},
      'claim_boundary':'Derived static indicators only. Presence does not prove runtime use; absence does not prove feature absence.'
    }
    out=pathlib.Path(args.out); out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(doc,indent=2,sort_keys=True)+'\n',encoding='utf-8')
    print(json.dumps({k:doc[k] for k in ('files_scanned','feature_markers','library_markers','protocol_markers','manifest')},indent=2))
    return 0

if __name__=='__main__': raise SystemExit(main())
