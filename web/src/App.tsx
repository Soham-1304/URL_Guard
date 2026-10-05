import { useState, useEffect } from 'react';
import { BackgroundCanvas } from './components/BackgroundCanvas';
import { Navbar } from './components/Navbar';
import { OverviewPage } from './components/OverviewPage';
import { DashboardPage } from './components/DashboardPage';
import { TestPage } from './components/TestPage';
import { StoryPage } from './components/StoryPage';
import { Footer } from './components/Footer';

function App() {
  const getHashRoute = () => {
    const hash = window.location.hash.replace(/^#/, '');
    return hash || '/';
  };

  const [route, setRoute] = useState<string>(getHashRoute);

  useEffect(() => {
    const handleHashChange = () => {
      const current = getHashRoute();
      setRoute(current);
      window.scrollTo(0, 0);

      // Title updates
      if (current === '/dashboard') {
        document.title = 'URL-Guard · Dashboard';
      } else if (current === '/test') {
        document.title = 'URL-Guard · Try it';
      } else if (current === '/story') {
        document.title = 'URL-Guard · Story';
      } else {
        document.title = 'URL-Guard';
      }
    };

    window.addEventListener('hashchange', handleHashChange);
    handleHashChange();

    return () => window.removeEventListener('hashchange', handleHashChange);
  }, []);

  const isOverview = route === '/' || route === '' || route === '/home';

  return (
    <>
      {/* Background canvas runs strictly on the Overview hero page only */}
      {isOverview && <BackgroundCanvas />}

      <Navbar currentRoute={route} />

      {isOverview && <OverviewPage />}
      {route === '/dashboard' && <DashboardPage />}
      {route === '/test' && <TestPage />}
      {route === '/story' && <StoryPage />}

      <Footer />
    </>
  );
}

export default App;
