import type {DirectionId,DirectionImplementation} from '../types.js';
import {D01,D02,D03,D04,D05} from './grid.js';
import {D06,D07} from './control-flow.js';
import {D08,D09} from './abi.js';
import {D10,D11} from './protocol.js';
import {D12,D13,D14} from './geometry.js';
import {D15,D16,D17} from './compatibility.js';

/**
 * The direction registry.
 *
 * This module is the only place that imports more than one direction file.
 * The individual direction files never import each other: a direction may
 * only use the corpus parser that lives in its own file.
 */
const IMPLEMENTATIONS:DirectionImplementation[]=[
 D01 as DirectionImplementation,
 D02 as DirectionImplementation,
 D03 as DirectionImplementation,
 D04 as DirectionImplementation,
 D05 as DirectionImplementation,
 D06 as DirectionImplementation,
 D07 as DirectionImplementation,
 D08 as DirectionImplementation,
 D09 as DirectionImplementation,
 D10 as DirectionImplementation,
 D11 as DirectionImplementation,
 D12 as DirectionImplementation,
 D13 as DirectionImplementation,
 D14 as DirectionImplementation,
 D15 as DirectionImplementation,
 D16 as DirectionImplementation,
 D17 as DirectionImplementation,
];

/** The implementation of one direction, or null when the direction is unknown. */
export function directionImplementation(directionId:string):DirectionImplementation|null{
 const found=IMPLEMENTATIONS.find((implementation)=>implementation.direction_id===directionId);
 return found===undefined?null:found;
}

/** Every registered direction identifier. */
export function registeredDirectionIds():DirectionId[]{
 return IMPLEMENTATIONS.map((implementation)=>implementation.direction_id);
}
