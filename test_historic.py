import requests, time

headers = {'Authorization': 'Bearer super-secret-local-key'}
job_id = '27cc1f56-2bf0-41ba-b1a9-8ddc92dc87eb'

print('Aguardando scan...')
for i in range(20):
    time.sleep(3)
    r = requests.get('http://localhost:8000/api/jobs/' + job_id, headers=headers)
    st = r.json().get('status')
    print('  [' + str(i*3) + 's] Status: ' + st)
    if st in ('completed', 'failed'):
        break

r = requests.get('http://localhost:8000/api/jobs/' + job_id + '/results', headers=headers)
print('RESULTS STATUS: ' + str(r.status_code))
if r.ok:
    data = r.json()
    findings = data.get('findings', [])
    print('FINDINGS: ' + str(len(findings)))
    for f in findings[:5]:
        sev = f.get('severity') or 'N/A'
        title = f.get('title') or 'N/A'
        print('  [' + sev + '] ' + title)
else:
    print('ERROR: ' + r.text)
