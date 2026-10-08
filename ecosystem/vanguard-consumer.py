"""Use the real Vanguard consumer without starting the Discord gateway."""
import json
import sys
import os
sys.path.insert(0, os.path.join(os.environ['ECOSYSTEM_ROOT'], 'discord-bots'))
import thingamabot
result = thingamabot.fetch_continental_me_sync(sys.stdin.read().strip())
print(json.dumps({'ok': result['ok'], 'subject': (result.get('user') or {}).get('userId')}))
