// The standard ShadCN-Svelte utility shim: a class-name combiner
// that merges Tailwind classes intelligently (so `bg-red-500` later
// in the chain wins over `bg-red-200` earlier).
import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

export function cn(...inputs: ClassValue[]): string {
	return twMerge(clsx(inputs));
}
