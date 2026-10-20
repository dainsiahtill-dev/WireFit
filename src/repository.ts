import {readFile} from 'node:fs/promises';
import {CaseStore} from './store.js';
import {readJson,validateSchema,semanticHash,sourceHash,sha256,assert} from './shared.js';
import {validateBvModel} from './model.js';
import {validateNumericModel} from './numeric.js';
import type {Model,ArtifactRef} from './types.js';
export function validateModel(value:unknown):Model{
 validateSchema('model',value);return (value as Model).kind==='bv_dag'?validateBvModel(value):validateNumericModel(value);
}
export async function importModel(store:CaseStore,input:unknown){
 const model=validateModel(typeof input==='string'?await readJson(input):structuredClone(input));
 const artifact=typeof input==='string'?await store.putArtifact(await readFile(input),'application/json'):await store.putJson(model);
 const identity={model_id:model.model_id,semantic_sha256:semanticHash(model),source_envelope_sha256:sourceHash(model),artifact};
 await store.putObject('models',model.model_id,model);
 await store.putObject('reports','modelmeta_'+sha256(model.model_id).slice(0,32),identity);
 return identity;
}
export async function loadModel(store:CaseStore,modelId:string):Promise<Model>{
 const model=validateModel(await store.getObject('models',modelId));
 const identity=await store.getObject<{semantic_sha256:string;source_envelope_sha256:string;artifact:ArtifactRef}>('reports','modelmeta_'+sha256(modelId).slice(0,32));
 assert(identity.semantic_sha256===semanticHash(model)&&identity.source_envelope_sha256===sourceHash(model),'MODEL_IDENTITY_CHANGED','Stored model identity changed');
 await store.readArtifact(identity.artifact);return model;
}
