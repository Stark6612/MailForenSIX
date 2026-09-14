import { useEffect, useRef, useMemo } from 'react';
import { gsap } from 'gsap';
import { ScrollTrigger } from 'gsap/ScrollTrigger';

import './ScrollReveal.css';

if (typeof window !== 'undefined') {
  gsap.registerPlugin(ScrollTrigger);
}

const ScrollReveal = ({
  children,
  scrollContainerRef,
  enableBlur = true,
  baseOpacity = 0.1,
  baseRotation = 3,
  blurStrength = 4,
  containerClassName = '',
  textClassName = '',
  rotationEnd = 'bottom bottom',
  wordAnimationEnd = 'bottom bottom',
  as = 'div'
}) => {
  const containerRef = useRef(null);

  const isString = typeof children === 'string';

  const splitText = useMemo(() => {
    if (!isString) return children;
    return children.split(/(\s+)/).map((word, index) => {
      if (word.match(/^\s+$/)) return word;
      return (
        <span className="word" key={index}>
          {word}
        </span>
      );
    });
  }, [children, isString]);

  useEffect(() => {
    const el = containerRef.current;
    if (!el || typeof window === 'undefined') return;

    const scroller = scrollContainerRef && scrollContainerRef.current ? scrollContainerRef.current : window;

    const ctx = gsap.context(() => {
      if (baseRotation !== 0) {
        gsap.fromTo(
          el,
          { transformOrigin: '0% 50%', rotate: baseRotation },
          {
            ease: 'none',
            rotate: 0,
            scrollTrigger: {
              trigger: el,
              scroller,
              start: 'top bottom',
              end: rotationEnd,
              scrub: true
            }
          }
        );
      }

      const wordElements = el.querySelectorAll('.word');
      if (wordElements.length > 0) {
        gsap.fromTo(
          wordElements,
          { opacity: baseOpacity, willChange: 'opacity' },
          {
            ease: 'none',
            opacity: 1,
            stagger: 0.05,
            scrollTrigger: {
              trigger: el,
              scroller,
              start: 'top bottom-=20%',
              end: wordAnimationEnd,
              scrub: true
            }
          }
        );

        if (enableBlur) {
          gsap.fromTo(
            wordElements,
            { filter: `blur(${blurStrength}px)` },
            {
              ease: 'none',
              filter: 'blur(0px)',
              stagger: 0.05,
              scrollTrigger: {
                trigger: el,
                scroller,
                start: 'top bottom-=20%',
                end: wordAnimationEnd,
                scrub: true
              }
            }
          );
        }
      } else if (!isString) {
        gsap.fromTo(
          el,
          { opacity: baseOpacity, y: 20 },
          {
            ease: 'power2.out',
            opacity: 1,
            y: 0,
            scrollTrigger: {
              trigger: el,
              scroller,
              start: 'top bottom-=10%',
              end: 'top center+=25%',
              scrub: 0.8
            }
          }
        );
      }
    }, el);

    return () => ctx.revert();
  }, [scrollContainerRef, enableBlur, baseRotation, baseOpacity, rotationEnd, wordAnimationEnd, blurStrength, isString]);

  const Component = as;

  if (!isString) {
    return (
      <Component ref={containerRef} className={`scroll-reveal ${containerClassName}`}>
        {children}
      </Component>
    );
  }

  return (
    <Component ref={containerRef} className={`scroll-reveal ${containerClassName}`}>
      <p className={`scroll-reveal-text ${textClassName}`}>{splitText}</p>
    </Component>
  );
};

export default ScrollReveal;
