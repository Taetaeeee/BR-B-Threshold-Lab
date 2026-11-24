import test from 'node:test';
import assert from 'node:assert/strict';
import { RESEARCH,getResult,hypothesisCheck,parseEvents,evaluateWindows,createDemoCSV,expectedLoss,rankThresholds,round } from '../engine.mjs';

test('연구 수치는 임계값 4~10, TP+FN=300 FP+TN=700, 총 1000',()=>{
  for(const mode of ['primary','stress']){
    assert.equal(RESEARCH[mode].rows.length,7);
    for(let t=4;t<=10;t++){
      const r=getResult(mode,t);assert.equal(r.tp+r.fn,300);assert.equal(r.fp+r.tn,700);
      assert.equal(r.tp+r.fn+r.fp+r.tn,1000);
    }
  }
});
test('논문 본 실험 5회, 6회 혼동행렬과 FNR/FPR',()=>{
  assert.deepEqual([getResult('primary',5).tp,getResult('primary',5).fn,getResult('primary',5).fp,getResult('primary',5).tn],[271,29,203,497]);
  assert.deepEqual([getResult('primary',6).tp,getResult('primary',6).fn,getResult('primary',6).fp,getResult('primary',6).tn],[233,67,102,598]);
  assert.equal(round(getResult('primary',5).fnr),9.67);
  assert.equal(round(getResult('primary',6).fnr),22.33);
  assert.equal(round(getResult('primary',5).fpr),29);
  assert.equal(round(getResult('primary',6).fpr),14.57);
});
test('사전 가설 불지지: FNR 감소, FPR 허용폭 초과',()=>{
  const h=hypothesisCheck();assert.equal(h.supported,false);
  assert.equal(round(h.fnrDecrease),12.67);
  assert.equal(round(h.fprIncrease),14.43);
});
test('7회: 본 실험 FPR 0 vs 사후 분포 변경 FPR 38.86',()=>{
  assert.equal(round(getResult('primary',7).fpr),0);
  assert.equal(round(getResult('stress',7).fpr),38.86);
});
test('연구 민감도 가정: 5%, FN 5배 => 본 실험 7회 최소',()=>{
  assert.equal(rankThresholds('primary',5,5)[0].threshold,7);
  assert.equal(round(expectedLoss(getResult('primary',7),5,5),4),.0783);
});
test('연구 민감도 가정: 30%, FN 5배 => 본 실험 4회 최소',()=>{
  assert.equal(rankThresholds('primary',30,5)[0].threshold,4);
  assert.equal(round(expectedLoss(getResult('primary',4),30,5),4),.313);
});
test('올바른 예시 CSV는 12개 5분 구간으로 집계',()=>{
  const data=parseEvents(createDemoCSV());assert.equal(data.errors.length,0);
  assert.equal(data.windows.length,12);
  assert.equal(data.rejectedEvents,0);
  const six=evaluateWindows(data.windows,6);
  assert.equal(six.tp+six.fn+six.fp+six.tn,12);
  assert.equal(six.rows.filter(w=>w.alert).length,six.tp+six.fp);
});
test('행별 오류 격리, 기존 유효 행은 유지',()=>{
  const src='timestamp_utc,ip,result,label\n2026-11-10T00:00:00Z,192.0.2.1,failure,normal\ninvalid,192.0.2.1,failure,normal\n2026-11-10T00:00:20Z,192.0.2.1,failure,attack\n2026-11-10T00:00:30Z,192.0.2.1,success,normal';
  const parsed=parseEvents(src);
  assert.equal(parsed.acceptedEvents,2);assert.equal(parsed.rejectedEvents,2);
  assert.equal(parsed.windows.length,1);assert.equal(parsed.windows[0].failures,1);
  assert.equal(parsed.windows[0].successes,1);
});
test('잘못된 입력·빈 입력에서 중단되지 않음',()=>{
  assert.doesNotThrow(()=>parseEvents(''));
  assert.doesNotThrow(()=>parseEvents(null));
  assert.deepEqual(evaluateWindows([],4).rows,[]);
  assert.throws(()=>getResult('primary',11),RangeError);
  assert.throws(()=>expectedLoss(getResult('primary',5),-1,1),RangeError);
});
test('최대 행 초과 및 CSV 스크립트 모양 입력도 실행 없이 거부',()=>{
  const malicious='<script>alert(1)</script>,127.0.0.1,failure,attack';
  const parsed=parseEvents(malicious);assert.equal(parsed.acceptedEvents,0);assert.ok(parsed.errors.length);
  const long='timestamp_utc,ip,result,label\n'+Array(3004).fill('2026-11-10T00:00:00Z,192.0.2.1,failure,normal').join('\n');
  const result=parseEvents(long);assert.equal(result.acceptedEvents,3000);assert.equal(result.rejectedEvents,4);
});
test('UTC 5분 경계는 IP마다 분리됨',()=>{
  const src='timestamp_utc,ip,result,label\n2026-11-10T00:04:59Z,192.0.2.1,failure,attack\n2026-11-10T00:05:00Z,192.0.2.1,failure,attack\n2026-11-10T00:04:59Z,192.0.2.2,failure,normal';
  assert.equal(parseEvents(src).windows.length,3);
});
