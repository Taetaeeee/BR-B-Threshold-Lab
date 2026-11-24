import { RESEARCH, getResult, hypothesisCheck, rankThresholds, expectedLoss, round, parseEvents, evaluateWindows, createDemoCSV } from './engine.mjs';

const state={mode:'primary', threshold:6, prevalence:5, fnCost:5, parsed:null};
const el=id=>document.getElementById(id);
const fmt=(v,d=2)=>Number(v).toFixed(d);
const count=n=>n.toLocaleString('ko-KR');
function make(tag,cls,text){const node=document.createElement(tag);if(cls)node.className=cls;if(text!==undefined)node.textContent=String(text);return node;}
function appendCell(row,tag,value,cls){const n=make(tag,cls,value);row.append(n);return n;}

function setMode(mode){
  if (!RESEARCH[mode]) return;
  state.mode=mode;
  for(const key of ['primary','stress']) el(`mode-${key}`).setAttribute('aria-pressed',String(key===mode));
  renderResearch();renderCost();
}
function setThreshold(threshold){
  const n=Number(threshold);
  if (!Number.isInteger(n)||n<4||n>10) return;
  state.threshold=n;el('threshold').value=String(n);
  renderResearch();renderDemo();renderCost();
}
function renderResearch(){
  const v=getResult(state.mode,state.threshold);
  const base=getResult(state.mode,6);
  el('threshold-big').innerHTML=`${v.threshold} <small>회 이상</small>`;
  el('mode-description').textContent=RESEARCH[state.mode].description;
  el('fnr-value').textContent=`${fmt(v.fnr)}%`;
  el('fpr-value').textContent=`${fmt(v.fpr)}%`;
  el('alerts-value').textContent=count(v.tp+v.fp);
  el('f1-value').textContent=fmt(v.f1,3);
  const deltas=[['fnr-delta',v.fnr-base.fnr,'누락률'],['fpr-delta',v.fpr-base.fpr,'오탐률']];
  for(const [id,delta,label] of deltas)el(id).textContent=`6회 대비 ${label} ${delta>=0?'+':'−'}${fmt(Math.abs(delta))}%p`;
  el('alerts-detail').textContent=`공격 ${count(v.tp)}건 / 정상 ${count(v.fp)}건`;
  el('matrix-threshold').textContent=`${v.threshold}회`;
  for(const key of ['tp','fn','fp','tn'])el(key).textContent=count(v[key]);
  const chart=el('tradeoff-chart');chart.replaceChildren();
  const tbody=el('research-table-body');tbody.replaceChildren();
  for(let t=4;t<=10;t++){
    const item=getResult(state.mode,t);
    const group=make('div',`bar-group${t===v.threshold?' selected':''}`);
    group.title=`${t}회 이상: 누락률 ${fmt(item.fnr)}%, 오탐률 ${fmt(item.fpr)}%`;
    const inner=make('div','bar-inner');
    for(const [type,value] of [['blue',item.fnr],['amber',item.fpr]]){
      const b=make('div',`bar ${type}`);
      b.style.height=`${Math.max(1,Math.min(100,value)/75*100)}%`;
      inner.append(b);
    }
    group.append(inner,make('span','bar-label',`${t}회`));chart.append(group);
    const tr=make('tr',t===v.threshold?'selected':'');
    for(const cell of [`${t}회`,item.tp,item.fn,item.fp,item.tn,`${fmt(item.fnr)}%`,`${fmt(item.fpr)}%`,fmt(item.f1,3)]) appendCell(tr,'td',cell);
    tbody.append(tr);
  }
  const h=hypothesisCheck();
  el('hypothesis-explanation').textContent=`본 실험의 사전 비교: 6회 → 5회에서 FNR은 ${fmt(h.fnrDecrease)}%p 감소했지만 FPR은 ${fmt(h.fprIncrease)}%p 증가했습니다. 허용 상한 ${fmt(h.allowedFprIncrease)}%p를 초과해 두 조건을 동시에 충족하지 못했습니다.`;
}
function renderDemo(){
  if(!state.parsed)return;
  const result=evaluateWindows(state.parsed.windows,state.threshold);
  el('demo-threshold').textContent=`${state.threshold}회`;
  el('sim-windows').textContent=count(result.rows.length);
  el('sim-alerts').textContent=count(result.tp+result.fp);
  el('sim-missed').textContent=count(result.fn);
  el('sim-false').textContent=count(result.fp);
  const status=el('simulation-badge');
  status.textContent=result.rows.length?'분석 완료':'유효한 자료 없음';
  const tbody=el('sim-table-body');tbody.replaceChildren();
  for(const w of result.rows.slice(0,60)){
    const tr=make('tr');
    const place=make('td');place.append(make('span','item-ip',w.ip),make('span','item-time',w.windowStart.replace('T',' ').replace('Z',' UTC')));
    tr.append(place);appendCell(tr,'td',w.failures);appendCell(tr,'td',w.label==='attack'?'공격':'정상');
    const statusText={tp:'공격 탐지',fn:'공격 누락',fp:'정상 오탐',tn:'정상 통과'}[w.classification];
    appendCell(tr,'td',statusText,`class-${w.classification}`);
    tbody.append(tr);
  }
  const errs=el('sim-errors');errs.replaceChildren();
  if(state.parsed.errors.length){
    const box=make('div','',`입력 점검: ${state.parsed.rejectedEvents}개 행 제외`);
    const list=make('ul');for(const message of state.parsed.errors)list.append(make('li','',message));
    errs.append(box,list);
  }
  el('parse-status').textContent=`정상 ${count(state.parsed.acceptedEvents)}건 · 제외 ${count(state.parsed.rejectedEvents)}건`;
  el('demo-note').textContent=`${result.rows.length>60?'앞 60개 구간만 표시합니다. ':''}본 데이터는 직접 입력한 예시 사건이며 연구의 1,000개 원자료가 아닙니다. 판정 결과는 연구 데이터 패널과 별도로 계산됩니다.`;
}
function runDemo(){
  state.parsed=parseEvents(el('csv-input').value);
  renderDemo();
}
function setPrevalence(v){
  state.prevalence=Number(v);el('prevalence').value=String(state.prevalence);
  el('prevalence-value').textContent=`${state.prevalence}%`;
  document.querySelectorAll('[data-prevalence]').forEach(b=>b.setAttribute('aria-pressed',String(Number(b.dataset.prevalence)===state.prevalence)));
  renderCost();
}
function renderCost(){
  const ordered=rankThresholds(state.mode,state.prevalence,state.fnCost,1);
  const best=ordered[0];const cur=getResult(state.mode,state.threshold);
  el('best-threshold').textContent=`${best.threshold}회`;
  el('best-description').textContent=`기대 손실 ${fmt(best.loss,4)} / 구간 · 현재 선택 ${cur.threshold}회: ${fmt(expectedLoss(cur,state.prevalence,state.fnCost,1),4)}`;
  const max=Math.max(...ordered.map(r=>r.loss),.000001);
  const container=el('cost-bars');container.replaceChildren();
  for(let t=4;t<=10;t++){
    const loss=ordered.find(v=>v.threshold===t).loss;
    const row=make('div',`cost-item${t===best.threshold?' best':''}`);
    row.append(make('span','cost-name',`${t}회`));
    const track=make('div','cost-track');const fill=make('div','cost-fill');fill.style.width=`${loss/max*100}%`;track.append(fill);
    row.append(track,make('span','cost-number',fmt(loss,4)));
    container.append(row);
  }
}
function reportText(){
  const r=getResult(state.mode,state.threshold),h=hypothesisCheck();
  const best=rankThresholds(state.mode,state.prevalence,state.fnCost,1)[0];
  const demo=state.parsed?evaluateWindows(state.parsed.windows,state.threshold):null;
  return [
    'THRESHOLD LAB | 연구 결과 적용 요약','기반 논문: 로그인 실패 횟수 임계값이 이상 접속 탐지 성능에 미치는 영향 (2026-11-10)',
    '연구 자료: 합성 인증 로그 (실운영 자료 아님)',`자료 구분: ${RESEARCH[state.mode].title}`,
    `탐지 기준: ${r.threshold}회 이상 / 동일 IP, UTC 5분 구간`,
    `TP=${r.tp} FN=${r.fn} FP=${r.fp} TN=${r.tn}`,
    `누락률(FNR)=${fmt(r.fnr)}% / 오탐률(FPR)=${fmt(r.fpr)}% / F1=${fmt(r.f1,3)}`,
    `사전 H1 검증: 6→5회, FNR -${fmt(h.fnrDecrease)}%p, FPR +${fmt(h.fprIncrease)}%p (허용 5.00%p), 지지되지 않음`,
    `비용 가정: 공격 비율 ${state.prevalence}% / FN 비용 ${state.fnCost} / FP 비용 1`,
    `해당 가정의 계산상 최저 기대 비용 기준: ${best.threshold}회 / ${fmt(best.loss,4)} (실제 정책 추천 아님)`,
    demo?`별도 데모 결과: ${demo.rows.length}구간, 경보 ${demo.tp+demo.fp}건, 공격 누락 ${demo.fn}건, 정상 오탐 ${demo.fp}건`:'별도 데모 미실행',
    '주의: 실제 운영 로그·개인정보를 저장하지 않습니다. 연구 원시 CSV가 아니라 논문의 발표 집계값 및 별도 데모를 이용했습니다.',
    '주의: 사후 분포 변경 결과는 H1 독립 검증이 아닙니다. 실제 환경으로 일반화할 수 없습니다.'
  ].join('\n');
}
function exportReport(){
  const blob=new Blob(['\uFEFF',reportText()],{type:'text/plain;charset=utf-8'});
  const url=URL.createObjectURL(blob);
  const a=document.createElement('a');a.href=url;a.download='threshold-lab-summary.txt';
  document.body.append(a);a.click();a.remove();
  setTimeout(()=>URL.revokeObjectURL(url),1000);
  el('export-status').textContent='현재 설정의 요약을 저장했습니다. 원시 로그는 포함하지 않았습니다.';
}
function init(){
  el('csv-input').value=createDemoCSV();
  el('mode-primary').addEventListener('click',()=>setMode('primary'));
  el('mode-stress').addEventListener('click',()=>setMode('stress'));
  el('threshold').addEventListener('input',e=>setThreshold(e.currentTarget.value));
  el('load-demo').addEventListener('click',()=>{el('csv-input').value=createDemoCSV();runDemo();});
  el('run-demo').addEventListener('click',runDemo);
  el('prevalence').addEventListener('input',e=>setPrevalence(e.currentTarget.value));
  document.querySelectorAll('[data-prevalence]').forEach(b=>b.addEventListener('click',()=>setPrevalence(b.dataset.prevalence)));
  el('fn-cost').addEventListener('change',e=>{state.fnCost=Number(e.currentTarget.value);renderCost();});
  el('export-report').addEventListener('click',exportReport);
  renderResearch();runDemo();renderCost();
}
init();
