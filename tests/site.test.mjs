import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync, statSync} from 'node:fs';
const html=readFileSync(new URL('../index.html',import.meta.url),'utf8');
const pdfPath=new URL('../research/T10_paper.pdf',import.meta.url);
test('최종 논문 PDF는 실제 파일이며 PDF 헤더가 있다',()=>{
  const data=readFileSync(pdfPath);
  assert.ok(statSync(pdfPath).size>100_000);
  assert.equal(data.subarray(0,5).toString('ascii'),'%PDF-');
});
test('첫 화면에서 논문 PDF를 정확한 상대 경로로 연다',()=>{
  assert.match(html,/href="\.\/research\/T10_paper\.pdf"/);
  assert.match(html,/최종 논문 PDF 열기/);
  assert.match(html,/rel="noopener noreferrer"/);
});
test('배포 버전과 스타일 캐시 버전이 일치한다',()=>{
  assert.match(html,/styles\.css\?v=0\.6\.0/);
  assert.match(html,/RESEARCH · V0\.6/);
});
