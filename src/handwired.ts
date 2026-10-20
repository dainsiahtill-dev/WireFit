import {Circuit} from '../vendor/handwired/src/runtime/numeric-ui-core.js';
import {WirefitError} from './shared.js';

export const HANDWIRED_COMMIT='257856e3b221140acb4cc4460626b850c0bd4ff1';
export const HANDWIRED_IDENTITY={name:'handwired',commit:HANDWIRED_COMMIT,source:'vendor/handwired/src/runtime/numeric-ui-core.ts',runtime:`node ${process.versions.node}`,engine:'Circuit.evaluateReference+backpropagateReference',boolean_gradient:'reject',index_gradient:'reject'} as const;
export type AffineRanges={a:readonly [number,number];b:readonly [number,number];x:readonly [number,number]};
export interface HandwiredSnapshot {output:number;gradients:{a:number;b:number};values:Float32Array;source_gradients:Float32Array;operations:number;compiled_layers:number;bitwise_compatible:boolean}
function finite(value:number,context:string):number {
  if(!Number.isFinite(value)||!Number.isFinite(Math.fround(value))) throw new WirefitError('NONFINITE',`${context} must be finite FP32`);
  return Math.fround(value);
}
/** Parameters are differentiable source cells, never frozen affine coefficients. */
export function createHandwiredAffine(ranges:AffineRanges) {
  const circuit=new Circuit(3);
  for(const [index,key] of (['a','b','x'] as const).entries()) {
    const interval=ranges[key];
    if(!Array.isArray(interval)||interval.length!==2||!Number.isFinite(interval[0])||!Number.isFinite(interval[1])||interval[0]>interval[1]) throw new WirefitError('INVALID_RANGE',`Invalid ${key} range`);
    circuit.assumeRange(circuit.source(index),interval[0],interval[1]);
  }
  const product=circuit.multiply(circuit.source(0),circuit.source(2));
  circuit.markRoundingPoint(product);
  const output=circuit.roundAffine([[product,1],[circuit.source(1),1]]);
  circuit.markRoundingPoint(output);
  const compiled=circuit.compileTensorProgram([output]);
  return {
    identity:{...HANDWIRED_IDENTITY},
    evaluate(a:number,b:number,x:number,upstream=1):HandwiredSnapshot {
      const source=new Float32Array([finite(a,'a'),finite(b,'b'),finite(x,'x')]);
      const seed=finite(upstream,'gradient');
      // validateSourceRanges is exercised on the actual source cells by this call.
      const values=circuit.evaluateReference(source);
      for(const value of values) if(!Number.isFinite(value)) throw new WirefitError('NONFINITE','Handwired intermediate is nonfinite');
      const seeds=new Float32Array(values.length);seeds[output]=seed;
      const gradients=circuit.backpropagateReference(values,seeds,{booleanGradient:'reject',indexGradient:'reject'});
      for(const value of gradients) if(!Number.isFinite(value)) throw new WirefitError('NONFINITE','Handwired gradient is nonfinite');
      const result=values[output]!;
      const reference=Math.fround(Math.fround(source[0]!*source[2]!)+source[1]!);
      // Upstream multiply/affine can canonicalize -0. Numeric training admits this;
      // final candidate execution always uses the independent exact FP32 evaluator.
      if(result!==reference) throw new WirefitError('BACKEND_MISMATCH','Handwired forward disagrees numerically with FP32 template',{result,reference});
      return {output:result,gradients:{a:gradients[0]!,b:gradients[1]!},values:new Float32Array(values),source_gradients:gradients.slice(0,3),operations:circuit.operations.length,compiled_layers:compiled.layers.length,bitwise_compatible:Object.is(result,reference)};
    }
  };
}
export function handwiredAffine(a:number,b:number,x:number,upstream:number,ranges:AffineRanges):HandwiredSnapshot {
  return createHandwiredAffine(ranges).evaluate(a,b,x,upstream);
}
