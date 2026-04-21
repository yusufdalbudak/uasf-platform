// React 19 + TypeScript 6 moved the JSX namespace off the global scope and
// onto `React.JSX`. Several of our existing components still reference the
// old global `JSX.Element` / `JSX.IntrinsicElements` shape. Rather than
// touching every call site, re-expose the React-namespaced types as globals
// so existing code keeps compiling.
//
// This is purely a type-level shim — no runtime code is emitted.

import type * as React from 'react';

declare global {
  namespace JSX {
    type Element = React.JSX.Element;
    type ElementClass = React.JSX.ElementClass;
    type ElementAttributesProperty = React.JSX.ElementAttributesProperty;
    type ElementChildrenAttribute = React.JSX.ElementChildrenAttribute;
    type LibraryManagedAttributes<C, P> = React.JSX.LibraryManagedAttributes<C, P>;
    type IntrinsicAttributes = React.JSX.IntrinsicAttributes;
    type IntrinsicClassAttributes<T> = React.JSX.IntrinsicClassAttributes<T>;
    type IntrinsicElements = React.JSX.IntrinsicElements;
  }
}

export {};
