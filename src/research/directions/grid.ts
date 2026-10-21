import {assert} from '../../shared.js';
import type {DevelopContext,EvaluateContext,FrozenCandidate,ResearchDirectionSpec} from '../types.js';

/**
 * The shared grid corpus parser of D01..D05.
 *
 * This file owns the parser; no other direction file may import it, and this
 * file imports no other direction file.
 */
export interface GridRow{
 id:string;
 width:number;
 height:number;
 node_stride:number;
 source_stride:number;
 labels:number[];
 machine_output:number[];
 candidate_output:number[];
 matched:boolean;
}

export interface GridModel{
 feature:string;
 a:number;
 b:number;
 c:number;
}

/** Loads the 896 recorded grid observations. */
export async function loadGridRows(ctx:DevelopContext|EvaluateContext):Promise<GridRow[]>{
 const rows=await ctx.corpus.jsonl<GridRow>('grid_observations');
 for(const row of rows)
  assert(typeof row.id==='string'&&Number.isInteger(row.width)&&Number.isInteger(row.height)&&Array.isArray(row.labels),
   'CORPUS_INVALID','Grid observation rows are malformed.');
 return rows;
}

/** The number of interior junctions: interior coordinates whose four adjacent cells differ. */
export function junctionCount(width:number,height:number,labels:number[]):number{
 let count=0;
 for(let y=1;y<height;y++)
  for(let x=1;x<width;x++){
   const northWest=labels[(y-1)*width+x-1]!,
    northEast=labels[(y-1)*width+x]!,
    southWest=labels[y*width+x-1]!,
    southEast=labels[y*width+x]!;
   if(!(northWest===northEast&&northEast===southWest&&southWest===southEast))count++;
  }
 return count;
}

/** The number of adjacent cell pairs (right and down) whose labels differ. */
export function transitionCount(width:number,height:number,labels:number[]):number{
 let count=0;
 for(let y=0;y<height;y++)
  for(let x=0;x<width;x++){
   if(x+1<width&&labels[y*width+x]!==labels[y*width+x+1])count++;
   if(y+1<height&&labels[y*width+x]!==labels[(y+1)*width+x])count++;
  }
 return count;
}

/** The number of cells whose label differs from the first cell. */
export function nonUniformCellCount(labels:number[]):number{
 const first=labels[0];
 return labels.reduce((total,value)=>total+(value===first?0:1),0);
}

/** The number of distinct labels in the grid. */
export function distinctLabelCount(labels:number[]):number{
 return new Set(labels).size;
}

/** The recorded node count of a row: the largest assigned node identifier plus one. */
export function observedNodeCount(row:GridRow):number{
 let largest=-1;
 for(const value of row.machine_output)if(value>largest)largest=value;
 return largest+1;
}

/** The feature vocabulary of the counting model. */
export const GRID_FEATURES:Record<string,(row:GridRow)=>number>={
 junction:(row)=>junctionCount(row.width,row.height,row.labels),
 transitions:(row)=>transitionCount(row.width,row.height,row.labels),
 nonuniform_cells:(row)=>nonUniformCellCount(row.labels),
 distinct_labels:(row)=>distinctLabelCount(row.labels),
};

/** Predicts the node count from a discovered model. */
export function predictCount(model:GridModel,row:GridRow):number{
 const feature=GRID_FEATURES[model.feature];
 assert(feature!==undefined,'MODEL_INVALID','Unknown grid feature: '+model.feature);
 return model.a*(row.width+row.height)+model.b+model.c*feature(row);
}

/**
 * Searches the bounded model space `count = a*(w+h) + b + c*feature`.
 * The enumeration order is fixed so the search is deterministic.
 */
export function searchCountModel(
 rows:readonly GridRow[],
):{model:GridModel|null;evaluated:number;exactOnFit:number}{
 let evaluated=0;
 let best:{model:GridModel;exact:number}|null=null;
 for(const feature of Object.keys(GRID_FEATURES))
  for(let a=0;a<=4;a++)
   for(let b=-4;b<=4;b++)
    for(let c=0;c<=3;c++){
     evaluated++;
     const model:GridModel={feature,a,b,c};
     let exact=0;
     for(const row of rows)if(predictCount(model,row)===observedNodeCount(row))exact++;
     if(best===null||exact>best.exact)best={model,exact};
     if(exact===rows.length)return {model,evaluated,exactOnFit:exact};
    }
 return {model:best===null?null:best.model,evaluated,exactOnFit:best===null?0:best.exact};
}

/** The affine-only baseline, fitted on the given rows. */
export function fitAffineBaseline(rows:readonly GridRow[]):{a:number;b:number;exact:number}{
 let best:{a:number;b:number;exact:number}|null=null;
 for(let a=0;a<=4;a++)
  for(let b=-4;b<=4;b++){
   let exact=0;
   for(const row of rows)if(a*(row.width+row.height)+b===observedNodeCount(row))exact++;
   if(best===null||exact>best.exact||(exact===best.exact&&a<best.a))best={a,b,exact};
  }
 return best===null?{a:0,b:0,exact:0}:best;
}

/**
 * The canonical encoding of a four-cell neighbourhood: the group index of
 * each cell in order of first appearance. Four equal cells encode as "0000".
 */
export function neighbourhoodKey(a:number,b:number,c:number,d:number):string{
 const groups=new Map<number,number>();
 const pattern=[a,b,c,d].map((value)=>{
  if(!groups.has(value))groups.set(value,groups.size);
  return groups.get(value)!;
 });
 return pattern.join('');
}

/** The junction indicator of one interior coordinate, or null outside the interior. */
export function junctionIndicator(width:number,height:number,labels:number[],x:number,y:number):number|null{
 if(x<1||x>=width||y<1||y>=height)return null;
 const northWest=labels[(y-1)*width+x-1]!,
  northEast=labels[(y-1)*width+x]!,
  southWest=labels[y*width+x-1]!,
  southEast=labels[y*width+x]!;
 return northWest===northEast&&northEast===southWest&&southWest===southEast?0:1;
}

/** The full node grid produced by the recorded numbering rule. */
export function referenceNodeGrid(row:GridRow):number[]{
 const nodes=new Array<number>(row.node_stride*(row.height+1)).fill(0);
 let next=0;
 for(const x of [0,row.width])
  for(let y=0;y<=row.height;y++){nodes[y*row.node_stride+x]=next;next++;}
 for(const y of [0,row.height])
  for(let x=1;x<row.width;x++){nodes[y*row.node_stride+x]=next;next++;}
 for(let y=1;y<row.height;y++)
  for(let x=1;x<row.width;x++){
   const indicator=junctionIndicator(row.width,row.height,row.labels,x,y)!;
   nodes[y*row.node_stride+x]=indicator===1?next:-1;
   if(indicator===1)next++;
  }
 return nodes;
}

// ---------------------------------------------------------------- D01 -----

export const D01={
 direction_id:'D01' as const,
 async develop(ctx:DevelopContext):Promise<{candidate:unknown;notes:string[]}>{
  const rows=await loadGridRows(ctx);
  const train=new Set(ctx.split.train),
   validation=new Set(ctx.split.validation);
  const trainRows=rows.filter((row)=>train.has(row.id)),
   fitRows=rows.filter((row)=>train.has(row.id)||validation.has(row.id));
  assert(trainRows.length>0&&fitRows.length>0,'SPLIT_EMPTY','D01 has no develop rows.');
  const search=searchCountModel(fitRows);
  const baseline=fitAffineBaseline(trainRows);
  const fitDetail=fitRows.map((row)=>({
   id:row.id,
   exact:search.model!==null&&predictCount(search.model,row)===observedNodeCount(row),
  }));
  const candidate={model:search.model,affine_baseline:{a:baseline.a,b:baseline.b}};
  const artifact={model:search.model,affine_baseline:candidate.affine_baseline,search_space_evaluated:search.evaluated,
   fit_rows:fitDetail,train_rows:trainRows.length,validation_rows:validation.size};
  ctx.corpus.registerDocument('develop/d01_model_search',artifact);
  await ctx.putArtifact(artifact);
  return {candidate,notes:[
   'The bounded model space was searched over '+String(search.evaluated)+' candidates on the train and validation rows only.',
   search.model===null?'No model in the bounded space reproduced every fit row.':'The discovered model is '+JSON.stringify(search.model)+'.',
  ]};
 },
 async evaluate(ctx:EvaluateContext,_spec:ResearchDirectionSpec,frozen:FrozenCandidate):Promise<{notes:string[]}>{
  const rows=await loadGridRows(ctx);
  const holdout=new Set(ctx.holdout);
  const candidate=frozen.candidate as {model:GridModel|null;affine_baseline:{a:number;b:number}};
  const holdoutRows=rows.filter((row)=>holdout.has(row.id));
  const detail=holdoutRows.map((row)=>{
   const observed=observedNodeCount(row);
   const predicted=candidate.model===null?null:predictCount(candidate.model,row);
   const affine=candidate.affine_baseline.a*(row.width+row.height)+candidate.affine_baseline.b;
   return {id:row.id,observed,predicted,exact:predicted===observed,affine_exact:affine===observed};
  });
  const artifact={rows:detail,holdout_rows:detail.length};
  ctx.corpus.registerDocument('evaluate/d01_holdout',artifact);
  await ctx.putArtifact(artifact);
  return {notes:['The frozen model was applied to '+String(detail.length)+' holdout rows.']};
 },
};

// ---------------------------------------------------------------- D02 -----

/** The bounded expression grammar of D02: an integer linear form over (r,c,W,H,J). */
export interface LinearForm{ r:number; c:number; w:number; h:number; j:number; k:number; }

export function evaluateForm(form:LinearForm,cell:{r:number;c:number;w:number;h:number;j:number}):number{
 return form.r*cell.r+form.c*cell.c+form.w*cell.w+form.h*cell.h+form.j*cell.j+form.k;
}

export type GridClass='left'|'right'|'top'|'bottom'|'interior'|'pad';

export interface GridCell{ r:number; c:number; w:number; h:number; j:number; }

export interface ClassSample{ cell:GridCell; id:number; }

/** The position class of a node-grid coordinate. */
export function gridClass(w:number,h:number,r:number,c:number):GridClass{
 if(c===0)return 'left';
 if(c===w)return 'right';
 if(r===0)return 'top';
 if(r===h)return 'bottom';
 if(c<w&&r<h)return 'interior';
 return 'pad';
}

/** The cell features of one node-grid coordinate. */
export function gridCell(row:GridRow,r:number,c:number):GridCell{
 const indicator=junctionIndicator(row.width,row.height,row.labels,c,r);
 return {r,c,w:row.width,h:row.height,j:indicator===null?0:indicator};
}

/** The reference ids of one row, grouped by position class. */
export function classSamples(row:GridRow):Map<GridClass,ClassSample[]>{
 const reference=referenceNodeGrid(row);
 const groups=new Map<GridClass,ClassSample[]>();
 for(let r=0;r<=row.height;r++)
  for(let c=0;c<row.node_stride;c++){
   const key=gridClass(row.width,row.height,r,c);
   if(!groups.has(key))groups.set(key,[]);
   groups.get(key)!.push({cell:gridCell(row,r,c),id:reference[r*row.node_stride+c]!});
  }
 return groups;
}

/**
 * Searches one position class for a linear form that reproduces the recorded
 * ids. The coefficient space is bounded and the enumeration order is fixed.
 */
export function searchClassForm(samples:readonly ClassSample[]):{form:LinearForm|null;evaluated:number;matched:number}{
 let evaluated=0;
 const best={form:null as LinearForm|null,matched:-1};
 const limit=samples.length;
 for(let a=-3;a<=3;a++)
  for(let b=-3;b<=3;b++)
   for(let c=-3;c<=3;c++)
    for(let d=-3;d<=3;d++)
     for(let e=-3;e<=3;e++)
      for(let k=-8;k<=8;k++){
       evaluated++;
       const form:LinearForm={r:a,c:b,w:c,h:d,j:e,k};
       let hits=0;
       for(const sample of samples)if(evaluateForm(form,sample.cell)===sample.id)hits++;
       if(hits>best.matched){best.form=form;best.matched=hits;}
       if(hits===limit)return {form,evaluated,matched:hits};
      }
 return {form:best.form,evaluated,matched:best.matched};
}

export const D02={
 direction_id:'D02' as const,
 async develop(ctx:DevelopContext):Promise<{candidate:unknown;notes:string[]}>{
  const rows=await loadGridRows(ctx);
  const train=new Set(ctx.split.train);
  const trainRows=rows.filter((row)=>train.has(row.id));
  assert(trainRows.length>0,'SPLIT_EMPTY','D02 has no develop rows.');
  const classes:GridClass[]=['left','right','top','bottom','interior','pad'];
  const forms:Partial<Record<GridClass,LinearForm|null>>={};
  let evaluated=0;
  for(const key of classes){
   const samples=trainRows.flatMap((row)=>classSamples(row).get(key)??[]);
   const distinct=new Map<string,ClassSample>();
   for(const sample of samples)distinct.set(sample.cell.r+':'+sample.cell.c+':'+sample.cell.w+':'+sample.cell.h+':'+sample.cell.j+':'+sample.id,sample);
   const search=searchClassForm([...distinct.values()]);
   evaluated+=search.evaluated;
   forms[key]=search.form;
  }
  const ruleCount=classes.filter((key)=>forms[key]!==undefined&&forms[key]!==null).length;
  const candidate={forms,rule_count:ruleCount};
  const artifact={forms,rule_count:ruleCount,candidates_evaluated:evaluated};
  ctx.corpus.registerDocument('develop/d02_search',artifact);
  await ctx.putArtifact(artifact);
  return {candidate,notes:[
   'The bounded grammar was searched per position class; '+String(evaluated)+' candidate forms were evaluated on training rows only.',
   'Classes with a reproducing form: '+classes.filter((key)=>forms[key]!==null&&forms[key]!==undefined).join(', ')+'.',
  ]};
 },
 async evaluate(ctx:EvaluateContext,_spec:ResearchDirectionSpec,frozen:FrozenCandidate):Promise<{notes:string[]}>{
  const rows=await loadGridRows(ctx);
  const holdout=new Set(ctx.holdout);
  const candidate=frozen.candidate as {forms:Partial<Record<GridClass,LinearForm|null>>};
  const holdoutRows=rows.filter((row)=>holdout.has(row.id));
  const produce=(forms:Partial<Record<GridClass,LinearForm|null>>,row:GridRow):number[]=>{
   const reference=referenceNodeGrid(row);
   const produced=new Array<number>(row.node_stride*(row.height+1)).fill(0);
   for(let r=0;r<=row.height;r++)
    for(let c=0;c<row.node_stride;c++){
     const key=gridClass(row.width,row.height,r,c);
     const form=forms[key];
     produced[r*row.node_stride+c]=form===null||form===undefined?-2:evaluateForm(form,gridCell(row,r,c));
    }
   return produced;
  };
  /*
   * The negative control: a seeded random search with the same per class
   * budget. It is fitted on the training rows and applied to the holdout
   * rows, exactly like the exhaustive search, so the comparison isolates the
   * search strategy rather than the data.
   */
  const trainRows=rows.filter((row)=>ctx.split.train.includes(row.id));
  const randomForms:Partial<Record<GridClass,LinearForm|null>>={};
  for(const key of ['left','right','top','bottom','interior','pad'] as GridClass[]){
   const samples=trainRows.flatMap((row)=>classSamples(row).get(key)??[]);
   const distinct=new Map<string,ClassSample>();
   for(const sample of samples)distinct.set(sample.cell.r+':'+sample.cell.c+':'+sample.cell.w+':'+sample.cell.h+':'+sample.cell.j+':'+sample.id,sample);
   randomForms[key]=randomSearchClassForm([...distinct.values()],ctx.budget.seed,key);
  }
  const detail=holdoutRows.map((row)=>{
   const reference=referenceNodeGrid(row);
   const produced=produce(candidate.forms,row);
   const random=produce(randomForms,row);
   const exact=produced.length===reference.length&&produced.every((value,index)=>value===reference[index]);
   const randomExact=random.length===reference.length&&random.every((value,index)=>value===reference[index]);
   return {id:row.id,exact,random_exact:randomExact};
  });
  const artifact={rows:detail,holdout_rows:detail.length};
  ctx.corpus.registerDocument('evaluate/d02_holdout',artifact);
  await ctx.putArtifact(artifact);
  return {notes:['The frozen program was applied to '+String(detail.length)+' holdout rows.']};
 },
};

/**
 * A seeded random search over the same per class form space.
 *
 * The generator is a deterministic linear congruential sequence so the
 * negative control is reproducible from the request budget seed.
 */
export function randomSearchClassForm(
 samples:readonly ClassSample[],
 seed:number,
 className:string,
 budget=2000,
):LinearForm|null{
 if(samples.length===0)return null;
 let state=(seed*2654435761+className.length*40503)>>>0;
 const next=():number=>{state=(state*1664525+1013904223)>>>0;return state;};
 let best:LinearForm|null=null,bestScore=-1;
 for(let attempt=0;attempt<budget;attempt++){
  const form:LinearForm={r:next()%7-3,c:next()%7-3,w:next()%7-3,h:next()%7-3,j:next()%7-3,k:next()%17-8};
  let hits=0;
  for(const sample of samples)if(evaluateForm(form,sample.cell)===sample.id)hits++;
  if(hits>bestScore){bestScore=hits;best=form;}
  if(hits===samples.length)break;
 }
 return best;
}

// ---------------------------------------------------------------- D03 -----

export interface PiecewiseModel{
 breakpoints:number[];
 pieces:{from:number;to:number;a:number;b:number;c:number}[];
 complete:boolean;
}

/**
 * Fits a piecewise affine model of (w,h) on the training rows.
 *
 * The model of this direction is a function of (w,h) **only**: it is the
 * affine form `a*w + b*h + c` with no label derived feature. A piecewise
 * model that used a label feature would not test the hypothesis this
 * direction declares.
 */
export function fitPiecewiseAffine(trainRows:readonly GridRow[]):PiecewiseModel{
 const widths=[...new Set(trainRows.map((row)=>row.width))].sort((left,right)=>left-right);
 const pieces:PiecewiseModel['pieces']=[];
 let complete=true;
 for(const width of widths){
  const rows=trainRows.filter((row)=>row.width===width);
  const fitted=fitAffineInWidthAndHeight(rows);
  if(fitted===null){complete=false;pieces.push({from:width,to:width,a:0,b:0,c:0});}
  else pieces.push({from:width,to:width,a:fitted.a,b:fitted.b,c:fitted.c});
 }
 return {breakpoints:widths,pieces,complete};
}

/** Finds the first affine form in (w,h) that reproduces every given row. */
function fitAffineInWidthAndHeight(rows:readonly GridRow[]):{a:number;b:number;c:number}|null{
 for(let a=0;a<=4;a++)
  for(let b=0;b<=4;b++)
   for(let c=-16;c<=16;c++){
    if(rows.every((row)=>a*row.width+b*row.height+c===observedNodeCount(row)))return {a,b,c};
   }
 return null;
}

export const D03={
 direction_id:'D03' as const,
 async develop(ctx:DevelopContext):Promise<{candidate:unknown;notes:string[]}>{
  const rows=await loadGridRows(ctx);
  const train=new Set(ctx.split.train);
  const trainRows=rows.filter((row)=>train.has(row.id));
  assert(trainRows.length>0,'SPLIT_EMPTY','D03 has no develop rows.');
  const model=fitPiecewiseAffine(trainRows);
  const candidate={model};
  const artifact={model,breakpoint_count:model.breakpoints.length};
  ctx.corpus.registerDocument('develop/d03_model',artifact);
  await ctx.putArtifact(artifact);
  return {candidate,notes:[
   'A piecewise affine model over the width axis was fitted on the training rows; '+String(model.breakpoints.length)+' breakpoints were used.',
   model.complete?'Every training width admitted an exact affine fit.':'At least one training width admitted no exact affine fit.',
  ]};
 },
 async evaluate(ctx:EvaluateContext,_spec:ResearchDirectionSpec,frozen:FrozenCandidate):Promise<{notes:string[]}>{
  const rows=await loadGridRows(ctx);
  const holdout=new Set(ctx.holdout);
  const candidate=frozen.candidate as {model:PiecewiseModel};
  const baseline=fitAffineBaseline(rows.filter((row)=>!holdout.has(row.id)));
  const holdoutRows=rows.filter((row)=>holdout.has(row.id));
  const detail=holdoutRows.map((row)=>{
   const piece=candidate.model.pieces.find((entry)=>row.width>=entry.from&&row.width<=entry.to);
   const observed=observedNodeCount(row);
   const predicted=piece===undefined?null:piece.a*row.width+piece.b*row.height+piece.c;
   const affine=baseline.a*(row.width+row.height)+baseline.b;
   return {id:row.id,observed,predicted,exact:predicted===observed,affine_exact:affine===observed};
  });
  const artifact={rows:detail,holdout_rows:detail.length};
  ctx.corpus.registerDocument('evaluate/d03_holdout',artifact);
  await ctx.putArtifact(artifact);
  return {notes:['The frozen piecewise model was applied to '+String(detail.length)+' holdout rows.']};
 },
};

// ---------------------------------------------------------------- D04 -----

export const D04={
 direction_id:'D04' as const,
 async develop(ctx:DevelopContext):Promise<{candidate:unknown;notes:string[]}>{
  const rows=await loadGridRows(ctx);
  const train=new Set(ctx.split.train);
  const trainRows=rows.filter((row)=>train.has(row.id));
  assert(trainRows.length>0,'SPLIT_EMPTY','D04 has no develop rows.');
  const observed=new Map<string,Set<number>>();
  for(const row of trainRows)
   for(let y=1;y<row.height;y++)
    for(let x=1;x<row.width;x++){
     const key=neighbourhoodKey(
      row.labels[(y-1)*row.width+x-1]!,row.labels[(y-1)*row.width+x]!,
      row.labels[y*row.width+x-1]!,row.labels[y*row.width+x]!);
     if(!observed.has(key))observed.set(key,new Set());
     observed.get(key)!.add(junctionIndicator(row.width,row.height,row.labels,x,y)!);
    }
  const entries=[...observed.entries()].map(([key,values])=>({key,indicator:values.size===1?[...values][0]!:2}));
  const conflicts=entries.filter((entry)=>entry.indicator===2).length;
  const table=entries.filter((entry)=>entry.indicator!==2);
  let affine:{a:number;b:number}|null=null;
  for(let a=0;a<=4&&affine===null;a++)
   for(let b=-4;b<=4;b++){
    const ok=trainRows.every((row)=>{
     let total=0;
     for(let y=1;y<row.height;y++)
      for(let x=1;x<row.width;x++){
       const key=neighbourhoodKey(
        row.labels[(y-1)*row.width+x-1]!,row.labels[(y-1)*row.width+x]!,
        row.labels[y*row.width+x-1]!,row.labels[y*row.width+x]!);
       const entry=table.find((candidate)=>candidate.key===key);
       if(entry===undefined)return false;
       total+=entry.indicator;
      }
     return a*(row.width+row.height)+b+total===observedNodeCount(row);
    });
    if(ok){affine={a,b};break;}
   }
  const candidate={table,affine,conflicts};
  const artifact={table,affine,conflicts};
  ctx.corpus.registerDocument('develop/d04_model',artifact);
  await ctx.putArtifact(artifact);
  return {candidate,notes:[
   'The neighbourhood lookup table was learned from '+String(trainRows.length)+' training rows; it holds '+String(table.length)+' entries with '+String(conflicts)+' conflicting keys.',
   affine===null?'No affine coefficient pair reproduces the training rows with this table.':'The affine term is '+JSON.stringify(affine)+'.',
  ]};
 },
 async evaluate(ctx:EvaluateContext,_spec:ResearchDirectionSpec,frozen:FrozenCandidate):Promise<{notes:string[]}>{
  const rows=await loadGridRows(ctx);
  const holdout=new Set(ctx.holdout);
  const candidate=frozen.candidate as {table:{key:string;indicator:number}[];affine:{a:number;b:number}|null};
  const baseline=fitAffineBaseline(rows.filter((row)=>!holdout.has(row.id)));
  const holdoutRows=rows.filter((row)=>holdout.has(row.id));
  const detail=holdoutRows.map((row)=>{
   const observed=observedNodeCount(row);
   let total=0,usable=true;
   for(let y=1;y<row.height&&usable;y++)
    for(let x=1;x<row.width&&usable;x++){
     const key=neighbourhoodKey(
      row.labels[(y-1)*row.width+x-1]!,row.labels[(y-1)*row.width+x]!,
      row.labels[y*row.width+x-1]!,row.labels[y*row.width+x]!);
     const entry=candidate.table.find((item)=>item.key===key);
     if(entry===undefined){usable=false;break;}
     total+=entry.indicator;
    }
   const predicted=candidate.affine===null||!usable?null:candidate.affine.a*(row.width+row.height)+candidate.affine.b+total;
   const affine=baseline.a*(row.width+row.height)+baseline.b;
   return {id:row.id,observed,predicted,exact:predicted===observed,affine_exact:affine===observed};
  });
  const artifact={rows:detail,holdout_rows:detail.length};
  ctx.corpus.registerDocument('evaluate/d04_holdout',artifact);
  await ctx.putArtifact(artifact);
  return {notes:['The frozen lookup table was applied to '+String(detail.length)+' holdout rows.']};
 },
};

// ---------------------------------------------------------------- D05 -----

/** An MBA style encoding of an integer count, used as the negative control corpus. */
export function mbaEncode(value:number):number{
 return (((value^0x5a5a)-0x5a5a)^0x5a5a)>>>0;
}

export const D05={
 direction_id:'D05' as const,
 async develop(ctx:DevelopContext):Promise<{candidate:unknown;notes:string[]}>{
  const rows=await loadGridRows(ctx);
  const train=new Set(ctx.split.train),
   validation=new Set(ctx.split.validation);
  const fitRows=rows.filter((row)=>train.has(row.id)||validation.has(row.id));
  assert(fitRows.length>0,'SPLIT_EMPTY','D05 has no develop rows.');
  const search=searchCountModel(fitRows);
  const model=search.model;
  const ops=model===null?[]:[
   {kind:'add',detail:'width + height'},
   {kind:'mul',detail:'2 * (width + height)'},
   {kind:'eq4',detail:'four adjacent cell labels all equal'},
   {kind:'sum',detail:'sum of junction indicators over interior coordinates'},
   {kind:'add',detail:'affine term + junction sum'},
  ];
  const candidate={model,ops,op_count:ops.length};
  const artifact={model,ops,op_count:ops.length,fit_rows:fitRows.map((row)=>({
   id:row.id,
   exact:model!==null&&predictCount(model,row)===observedNodeCount(row),
  }))};
  ctx.corpus.registerDocument('develop/d05_program',artifact);
  await ctx.putArtifact(artifact);
  return {candidate,notes:[
   'The integer program was derived from the bounded model search and has '+String(ops.length)+' operations.',
   'The MBA negative control encoding is x -> (((x ^ 0x5a5a) - 0x5a5a) ^ 0x5a5a).',
  ]};
 },
 async evaluate(ctx:EvaluateContext,_spec:ResearchDirectionSpec,frozen:FrozenCandidate):Promise<{notes:string[]}>{
  const rows=await loadGridRows(ctx);
  const holdout=new Set(ctx.holdout);
  const candidate=frozen.candidate as {model:GridModel|null};
  const holdoutRows=rows.filter((row)=>holdout.has(row.id));
  const detail=holdoutRows.map((row)=>{
   const observed=observedNodeCount(row);
   const predicted=candidate.model===null?null:predictCount(candidate.model,row);
   const encoded=mbaEncode(observed);
   return {id:row.id,observed,predicted,encoded,exact:predicted===observed,mba_exact:predicted===encoded};
  });
  const artifact={rows:detail,holdout_rows:detail.length};
  ctx.corpus.registerDocument('evaluate/d05_holdout',artifact);
  await ctx.putArtifact(artifact);
  return {notes:['The frozen integer program was applied to '+String(detail.length)+' holdout rows and to the MBA encoded variant.']};
 },
};
