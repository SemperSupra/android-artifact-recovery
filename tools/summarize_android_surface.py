#!/usr/bin/env python3
from __future__ import annotations
import argparse, collections, json, pathlib, re
from urllib.parse import urlparse

KEYWORDS = [
    'voice','audio','speech','realtime','webrtc','websocket','camera','photo','image','upload',
    'file','attachment','screen','accessibility','capture','search','browse','browser','connector',
    'plugin','memory','project','task','notification','share','widget','auth','oauth','pkce',
    'device_code','devicecode','login','codex','canvas','conversation','history','model','tool',
    'location','bluetooth','nfc','biometric','deeplink','deep_link','quicktile','quick_tile',
    'assistant','webview','sse','grpc','graphql','websocket','stream','temporary'
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
    'websocket_surface': ['websocket', 'wss://'],
    'server_sent_events': ['text/event-stream', 'eventsource'],
    'grpc_surface': ['io/grpc/', 'grpc'],
    'graphql_surface': ['graphql'],
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
    'image_generation': ['imagegeneration', 'image_generation', 'imagegen'],
    'image_edit': ['imageedit', 'image_edit'],
    'memory_surface': ['memory'],
    'projects_surface': ['project'],
    'canvas_surface': ['canvas'],
    'search_surface': ['search'],
    'quick_tile': ['quicktileservice', 'quick_tile', 'quicktile'],
    'widget_surface': ['widgetreceiver', 'widgetinstallbroadcastreceiver', 'appwidget'],
    'voice_interaction_service': ['voiceinteractionservice', 'bind_voice_interaction'],
    'accessibility_service': ['accessibilityservice', 'bind_accessibility_service'],
    'biometric_surface': ['use_biometric', 'use_fingerprint', 'biometricprompt'],
    'location_surface': ['access_fine_location', 'access_coarse_location'],
    'nfc_surface': ['android.permission.nfc', 'nfcadapter'],
}
URL_RE = re.compile(r'https?://[^\s"\'<>\\)]+', re.I)
URI_RE = re.compile(r'(?<![A-Za-z0-9+.-])([a-z][a-z0-9+.-]{1,31})://([^\s"\'<>\\)]+)', re.I)
HOSTISH_RE = re.compile(r'(?<![A-Za-z0-9_-])(?:[A-Za-z0-9-]+\\.)+(?:com|net|org|io|ai|dev|app)(?![A-Za-z0-9_-])', re.I)
ROUTE_RE = re.compile(
    r'["\'](/(?:v\\d+|api|backend-api|accounts|auth|oauth|realtime|voice|files?|uploads?|'
    r'conversations?|models?|connectors?|codex|share|search|images?|audio|ws|events|tools?)'
    r'[A-Za-z0-9_./?=&%{}:$@+~\\-]{0,220})["\']',
    re.I,
)
PERMISSION_RE = re.compile(r'android\.permission\.[A-Z0-9_]+')
AAPT_COMPONENT_RE = re.compile(r'^\s*E:\s+(activity|activity-alias|service|receiver|provider)\b', re.M)
AAPT_NAME_RE = re.compile(r'android:name[^=]*="([^"]+)"')

def read_text(path: pathlib.Path) -> str:
    try: return path.read_text(encoding='utf-8', errors='ignore')
    except OSError: return ''

def sanitize_url(raw: str) -> str | None:
    try:
        parsed=urlparse(raw)
    except ValueError:
        return None
    if not parsed.scheme or not parsed.hostname:
        return None
    host=parsed.hostname.lower().strip('.')
    port=f":{parsed.port}" if parsed.port else ''
    path=parsed.path or '/'
    # Deliberately drop userinfo, query and fragment. They may contain account,
    # experiment, authorization or other non-public values.
    return f"{parsed.scheme.lower()}://{host}{port}{path}"

def sanitize_route(raw: str) -> str:
    # Preserve only route shape; query/fragment values are not durable evidence.
    return raw.split('?',1)[0].split('#',1)[0]

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
    openai_urls=collections.Counter(); custom_uris=collections.Counter(); route_candidates=collections.Counter()
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
            raw=m.group(0)
            try: h=urlparse(raw).hostname
            except ValueError: h=None
            if h:
                host=h.lower().strip('.'); hosts[host]+=1
                if any(s in host for s in ('openai','chatgpt','oaistatic')):
                    safe=sanitize_url(raw)
                    if safe: openai_urls[safe]+=1
        for m in URI_RE.finditer(text):
            scheme=m.group(1).lower()
            if scheme not in ('http','https'):
                # Preserve only scheme + first path segment; do not retain opaque
                # callback/query values from account/deep-link material.
                body=m.group(2).split('?',1)[0].split('#',1)[0]
                first='/'.join(body.split('/')[:2])
                custom_uris[f"{scheme}://{first}"]+=1
        for m in ROUTE_RE.finditer(text):
            route_candidates[sanitize_route(m.group(1))]+=1
        for m in HOSTISH_RE.finditer(text): hosts[m.group(0).lower().strip('.')]+=1
        if any(k in rel_l for k in ('openai','chatgpt','voice','realtime','auth','oauth','accessibility','screen','image','camera','conversation','codex')):
            if len(named_paths)<500 and len(path.stem)<160: named_paths.append(rel)
    manifest=read_text(pathlib.Path(args.manifest)); permissions_text=read_text(pathlib.Path(args.permissions)) if args.permissions else ''
    openai_hosts=[h for h,c in hosts.most_common() if any(s in h for s in ('openai','chatgpt','oaistatic'))][:200]
    other_hosts=[h for h,c in hosts.most_common() if h not in openai_hosts][:200]
    protocol={name:{'file_count':len(paths),'sample_paths':sorted(set(paths))[:30]} for name,paths in marker_files.items() if paths}
    doc={
      'schema':'aar-derived-android-surface/v2','files_scanned':len(files),'extensions':dict(ext_counts.most_common()),
      'feature_markers':{k:keyword_hits[k] for k in KEYWORDS if keyword_hits[k]},
      'library_markers':{k:v for k,v in library_hits.items() if v}, 'protocol_markers':protocol,
      'network_hosts':{'openai_related':openai_hosts,'other_observed':other_hosts},
      'endpoint_candidates':{
        'sanitized_openai_urls':[u for u,c in openai_urls.most_common(300)],
        'sanitized_route_shapes':[r for r,c in route_candidates.most_common(500)],
        'custom_uri_shapes':[u for u,c in custom_uris.most_common(200)],
        'redaction':'userinfo/query/fragment and opaque deep-link tails are intentionally omitted'
      },
      'manifest':parse_manifest(manifest,permissions_text), 'interesting_paths':sorted(set(named_paths))[:500],
      'limits':{
        'max_files':args.max_files,'max_interesting_paths':500,'max_hosts_each':200,
        'max_protocol_sample_paths':30,'max_openai_urls':300,'max_route_shapes':500,'max_custom_uri_shapes':200
      },
      'claim_boundary':(
        'Derived static indicators only. Presence does not prove runtime use; absence does not prove feature absence. '
        'Observed first-party endpoint/URI shapes are discovery evidence, not supported third-party integration contracts.'
      )
    }
    out=pathlib.Path(args.out); out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(doc,indent=2,sort_keys=True)+'\n',encoding='utf-8')
    print(json.dumps({k:doc[k] for k in ('files_scanned','feature_markers','library_markers','protocol_markers','endpoint_candidates','manifest')},indent=2))
    return 0

if __name__=='__main__': raise SystemExit(main())
