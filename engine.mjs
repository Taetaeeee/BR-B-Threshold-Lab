/**
 * Threshold Lab research engine.
 * Source: T10 C research paper, 2026-11-10, Table 1 and post-hoc Table 2.
 * These are published aggregate counts (not the original raw logs).
 */
export const PAPER_TITLE = '로그인 실패 횟수 임계값이 이상 접속 탐지 성능에 미치는 영향';
export const RESEARCH = Object.freeze({
  primary: {
    title: '본 실험 · 1,000개 구간',
    description: '사전 가설 검증에 사용한 합성 로그. 공격 300구간, 정상 700구간. 정상 실패 횟수는 최대 6회로 생성됨.',
    exploratory: false,
    rows: [
      [4,300,0,313,387], [5,271,29,203,497], [6,233,67,102,598],
      [7,206,94,0,700], [8,170,130,0,700], [9,127,173,0,700], [10,101,199,0,700]
    ]
  },
  stress: {
    title: '사후 분포 변경 · 1,000개 구간',
    description: '연구 결과를 본 뒤 별도로 만든 탐색적 합성 자료. 공격은 2~12회, 정상은 0~10회까지 실패가 발생하도록 분포를 변경함.',
    exploratory: true,
    rows: [
      [4,250,50,440,260], [5,218,82,385,315], [6,194,106,322,378],
      [7,167,133,272,428], [8,140,160,209,491], [9,117,183,148,552], [10,86,214,73,627]
    ]
  }
});

const ratio = (a, b) => b === 0 ? 0 : a / b;
export function summarizeCounts({tp,fn,fp,tn}) {
  return {
    tp,fn,fp,tn,
    fnr: ratio(fn,tp+fn)*100,
    fpr: ratio(fp,fp+tn)*100,
    precision: ratio(tp,tp+fp)*100,
    recall: ratio(tp,tp+fn)*100,
    f1: ratio(2*tp,2*tp+fp+fn)
  };
}
export function getResult(mode, threshold) {
  const source=RESEARCH[mode];
  if (!source) throw new RangeError('알 수 없는 연구 자료 구분');
  if (!Number.isInteger(threshold) || threshold < 4 || threshold > 10) throw new RangeError('임계값은 4~10회입니다');
  const values=source.rows.find(r=>r[0]===threshold);
  if (!values) throw new Error('연구 데이터 누락');
  return { threshold, ...summarizeCounts({tp:values[1],fn:values[2],fp:values[3],tn:values[4]}) };
}
export const round = (number, digits=2) => Number(number.toFixed(digits));
export function hypothesisCheck() {
  const five=getResult('primary',5), six=getResult('primary',6);
  return {
    fnrDecrease: six.fnr-five.fnr,
    fprIncrease: five.fpr-six.fpr,
    allowedFprIncrease:5,
    supported:five.fnr<six.fnr && five.fpr-six.fpr<=5
  };
}
/** Assumption-based misclassification loss per window, NOT empirical operating cost. */
export function expectedLoss(metric, prevalencePercent, fnCost=1, fpCost=1) {
  if (![prevalencePercent,fnCost,fpCost].every(Number.isFinite) || prevalencePercent<0 || prevalencePercent>100 || fnCost<0 || fpCost<0) {
    throw new RangeError('공격 비율 및 비용은 올바른 범위의 수여야 합니다');
  }
  const p=prevalencePercent/100;
  return p*fnCost*(metric.fnr/100)+(1-p)*fpCost*(metric.fpr/100);
}
export function rankThresholds(mode, prevalencePercent, fnCost=1, fpCost=1) {
  return RESEARCH[mode].rows.map(row=>{
    const metric=getResult(mode,row[0]);
    return {threshold:metric.threshold,loss:expectedLoss(metric,prevalencePercent,fnCost,fpCost)};
  }).sort((a,b)=>a.loss-b.loss || a.threshold-b.threshold);
}
/**
 * Input format: timestamp_utc,ip,result,label
 * result: failure | success ; label: attack | normal
 * UTC timestamps must be strict ISO 8601 with Z suffix.
 * Events grouped by (IP, floor(UTC epoch / 5 min)).
 * Labels are used ONLY for evaluation, never detection.
 */
export function parseEvents(csv, maxRows=3000) {
  const errors=[];
  const windows=new Map();
  if (typeof csv!=='string') return {windows:[], errors:['CSV는 문자열이어야 합니다.'], acceptedEvents:0, rejectedEvents:0};
  const lines=csv.replace(/^\uFEFF/,'').split(/\r?\n/);
  let acceptedEvents=0, rejectedEvents=0, contentRows=0;
  for (let i=0;i<lines.length;i++) {
    const original=lines[i].trim();
    if (!original || original.startsWith('#')) continue;
    if (/^timestamp_utc\s*,\s*ip\s*,\s*result\s*,\s*label$/i.test(original)) continue;
    contentRows++;
    if (contentRows>maxRows) {
      rejectedEvents++; if (contentRows===maxRows+1) errors.push(`${maxRows}행 한도를 넘는 행은 무시했습니다.`);
      continue;
    }
    const fields=original.split(',').map(x=>x.trim());
    let reason='';
    if (fields.length!==4) reason='4개 열(timestamp_utc,ip,result,label)이 필요합니다';
    const [timestamp,ip,result,label]=fields;
    if (!reason && !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(timestamp)) reason='UTC 시각 형식이 올바르지 않습니다';
    const epoch=Date.parse(timestamp ?? '');
    if (!reason && (!Number.isFinite(epoch) || new Date(epoch).toISOString()!==timestamp.replace('Z','.000Z'))) reason='존재하지 않는 시각입니다';
    if (!reason && !isIPv4(ip)) reason='IPv4 주소가 올바르지 않습니다';
    if (!reason && result!=='failure' && result!=='success') reason='결과는 failure 또는 success여야 합니다';
    if (!reason && label!=='attack' && label!=='normal') reason='정답 라벨은 attack 또는 normal이어야 합니다';
    const bucket=Math.floor(epoch/300000)*300000;
    const key=`${ip}|${bucket}`;
    if (!reason && windows.has(key) && windows.get(key).label!==label) reason='같은 IP·5분 구간에 상충하는 정답 라벨이 있습니다';
    if (reason) {
      rejectedEvents++;
      if (errors.length<12) errors.push(`${i+1}행: ${reason}`);
      continue;
    }
    if (!windows.has(key)) windows.set(key,{ip,windowStart:new Date(bucket).toISOString().replace('.000Z','Z'),failures:0,successes:0,label});
    windows.get(key)[result==='failure'?'failures':'successes']++;
    acceptedEvents++;
  }
  if (!contentRows) errors.push('데이터 행이 없습니다. 예시 데이터를 불러와 실행해 보세요.');
  if (acceptedEvents===0 && contentRows) errors.push('유효한 이벤트가 없어 탐지할 구간이 없습니다.');
  return { windows:[...windows.values()].sort((a,b)=>a.windowStart.localeCompare(b.windowStart)||a.ip.localeCompare(b.ip)),errors,acceptedEvents,rejectedEvents };
}
function isIPv4(ip) {
  const nums=ip?.split('.');
  return nums?.length===4 && nums.every(n=>/^(0|[1-9]\d{0,2})$/.test(n) && Number(n)<=255);
}
export function evaluateWindows(windows, threshold) {
  if (!Number.isInteger(threshold)||threshold<4||threshold>10) throw new RangeError('임계값은 4~10회입니다');
  let tp=0,fn=0,fp=0,tn=0;
  const evaluated=windows.map(w=>{
    const alert=w.failures>=threshold;
    const key=w.label==='attack'?(alert?'tp':'fn'):(alert?'fp':'tn');
    if(key==='tp')tp++; if(key==='fn')fn++; if(key==='fp')fp++; if(key==='tn')tn++;
    return {...w, alert, classification:key};
  });
  return {rows:evaluated,...summarizeCounts({tp,fn,fp,tn})};
}
/** Deterministic, explicitly fictional demo events, NOT the T10 raw 6,551 events. */
export function createDemoCSV() {
  const groups=[
    [3,'normal'],[4,'normal'],[5,'normal'],[5,'attack'],[6,'attack'],[7,'attack'],
    [8,'attack'],[9,'attack'],[10,'attack'],[4,'normal'],[6,'normal'],[11,'normal']
  ];
  const lines=['timestamp_utc,ip,result,label'];
  const base=Date.parse('2026-11-10T00:00:00Z');
  for(let i=0;i<groups.length;i++) {
    const [failCount,label]=groups[i];
    const ip=`192.0.2.${i+11}`;
    const start=base+i*300000;
    for(let j=0;j<failCount;j++){
      const at=start+Math.floor(j*270/failCount)*1000;
      lines.push(`${new Date(at).toISOString().replace('.000Z','Z')},${ip},failure,${label}`);
    }
    if(i%3===0) lines.push(`${new Date(start+280000).toISOString().replace('.000Z','Z')},${ip},success,${label}`);
  }
  return lines.join('\n');
}
