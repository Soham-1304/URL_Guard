import React from 'react';

interface NavbarProps {
  currentRoute: string;
}

export const Navbar: React.FC<NavbarProps> = ({ currentRoute }) => {
  return (
    <nav aria-label="Main">
      <div className="wrap">
        <a className="logo" href="#/">
          <i>▮</i> url-guard
        </a>
        <ul id="nav">
          <li>
            <a
              href="#/"
              aria-current={currentRoute === '/' || currentRoute === '' ? 'page' : undefined}
            >
              Overview
            </a>
          </li>
          <li>
            <a
              href="#/dashboard"
              aria-current={currentRoute === '/dashboard' ? 'page' : undefined}
            >
              Dashboard
            </a>
          </li>
          <li>
            <a
              href="#/test"
              aria-current={currentRoute === '/test' ? 'page' : undefined}
            >
              Try it
            </a>
          </li>
          <li>
            <a
              href="#/story"
              aria-current={currentRoute === '/story' ? 'page' : undefined}
            >
              Story
            </a>
          </li>
        </ul>
        <a
          className="gh"
          href="https://github.com/Soham-1304/URL_Guard"
          target="_blank"
          rel="noopener noreferrer"
        >
          GitHub
        </a>
      </div>
    </nav>
  );
};
