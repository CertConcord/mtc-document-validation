import test from 'node:test';
import assert from 'node:assert/strict';
import {assertPreservationLifetimes as validate} from './lifetimes.mjs';
const facts = () => [
  {chain:0,genTime:100,accuracy:1,poeUpperBound:101,validUntil:400,hashOID:'sha256'},
  {chain:1,genTime:200,accuracy:1,poeUpperBound:201,validUntil:500,hashOID:'sha512'},
];
const policy = () => ({at:300,dataValidUntil:150,hashValidUntil:{sha256:250,sha512:600}});
test('hash renewal extends protection past the original hash deadline',()=>assert.equal(validate(facts(),policy()),true));
test('protection deadlines and interval ordering reject gaps',()=>{
  for (const [change,code] of [
    [(r,p)=>p.dataValidUntil=101,'ERS_INITIAL_PROTECTION_LATE'],
    [(r)=>{r[1].genTime=100;r[1].poeUpperBound=101;},'ERS_INTERVAL_ORDER'],
    [(r)=>r[0].validUntil=201,'ERS_RENEWAL_LATE'],
    [(r,p)=>p.at=500,'ERS_FINAL_PROTECTION_EXPIRED'],
    [(r,p)=>delete p.hashValidUntil.sha256,'ERS_HASH_LIFETIME_REQUIRED'],
    [(r)=>{r[1].chain=0;r[1].hashOID='sha256';},'ERS_HASH_RENEWAL_LATE'],
  ]) {const r=facts(),p=policy();change(r,p);assert.throws(()=>validate(r,p),{code});}
});
test('unverified malformed facts are not accepted as a preservation result',()=>{
  const r=facts();r[0].poeUpperBound=1;assert.throws(()=>validate(r,policy()),{code:'ERS_RECORD_FACTS'});
});
test('integral-second entry rejects fractional and unsafe Number times',()=>{
  const fractional=facts();
  fractional[0].accuracy=0.01;
  fractional[0].poeUpperBound=fractional[0].genTime+0.01;
  assert.throws(()=>validate(fractional,policy()),{code:'ERS_RECORD_FACTS'});
  const unsafe=facts();unsafe[0].genTime=Number.MAX_SAFE_INTEGER+1;
  assert.throws(()=>validate(unsafe,policy()),{code:'ERS_RECORD_FACTS'});
  const fractionalPolicy=policy();fractionalPolicy.at=300.5;
  assert.throws(()=>validate(facts(),fractionalPolicy),{code:'ERS_PRESERVATION_POLICY'});
  const fractionalHash=policy();fractionalHash.hashValidUntil.sha256=250.5;
  assert.throws(()=>validate(facts(),fractionalHash),
    {code:'ERS_HASH_LIFETIME_REQUIRED'});
});
