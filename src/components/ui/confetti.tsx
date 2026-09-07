"use client";

import React, {
  type HTMLAttributes,
  forwardRef,
  useEffect,
  useImperativeHandle,
  useRef,
  useCallback,
} from "react";

import confetti, { type Options as ConfettiOptions } from "canvas-confetti";

import { cn } from "@/lib/utils";

export interface ConfettiRef {
  fire: (options?: ConfettiOptions) => void;
}

interface ConfettiProps extends HTMLAttributes<HTMLDivElement> {
  /**
   * Default options merged into every burst fired by this instance.
   */
  options?: ConfettiOptions;
  /**
   * Fire a celebration burst automatically once the component is mounted.
   */
  autoFire?: boolean;
  /**
   * Fire a burst automatically after mount with this delay (ms).
   * Used together with `autoFire` to let the card entrance animation finish.
   */
  autoFireDelay?: number;
}

const Confetti = forwardRef<ConfettiRef, ConfettiProps>(
  ({ options, autoFire = false, autoFireDelay = 0, className, children, ...rest }, ref) => {
    const canvasRef = useRef<HTMLCanvasElement>(null);
    const instanceRef = useRef<ReturnType<typeof confetti.create> | null>(null);
    const optionsRef = useRef<ConfettiOptions>(options ?? {});
    optionsRef.current = options ?? {};

    useEffect(() => {
      if (!canvasRef.current) return;
      const instance = confetti.create(canvasRef.current, {
        resize: true,
        useWorker: true,
      });
      instanceRef.current = instance;
      return () => {
        instance.reset();
        instanceRef.current = null;
      };
    }, []);

    const fire = useCallback((fireOptions?: ConfettiOptions) => {
      const opts = {
        ...optionsRef.current,
        ...fireOptions,
      };
      if (instanceRef.current) {
        instanceRef.current(opts);
      } else {
        confetti(opts);
      }
    }, []);

    useImperativeHandle(ref, () => ({ fire }), [fire]);

    useEffect(() => {
      if (!autoFire) return;
      const timer = setTimeout(() => fire(), autoFireDelay);
      return () => clearTimeout(timer);
    }, [autoFire, autoFireDelay, fire]);

    return (
      <div {...rest} className={cn("pointer-events-none overflow-hidden", className)}>
        {children}
        <canvas
          ref={canvasRef}
          className="pointer-events-none absolute inset-0 size-full"
          aria-hidden
        />
      </div>
    );
  },
);

Confetti.displayName = "Confetti";

export { Confetti };