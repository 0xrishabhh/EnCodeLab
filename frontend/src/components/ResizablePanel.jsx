import React, { useState } from 'react';

const ResizablePanel = ({
  children,
  width,
  minWidth = 200,
  maxWidth = 800,
  onResize,
  className = "",
  ...props
}) => {
  const [isResizing, setIsResizing] = useState(false);
  const [startX, setStartX] = useState(0);
  const [startWidth, setStartWidth] = useState(width);

  const handleMouseDown = (e) => {
    setIsResizing(true);
    setStartX(e.clientX);
    setStartWidth(width);
    document.body.style.cursor = 'col-resize';
    document.body.style.userSelect = 'none';
  };

  const handleMouseMove = (e) => {
    if (!isResizing) return;

    const deltaX = e.clientX - startX;
    const newWidth = Math.max(minWidth, Math.min(maxWidth, startWidth + deltaX));

    if (onResize) {
      onResize(newWidth);
    }
  };

  const handleMouseUp = () => {
    setIsResizing(false);
    document.body.style.cursor = '';
    document.body.style.userSelect = '';
  };

  React.useEffect(() => {
    if (isResizing) {
      document.addEventListener('mousemove', handleMouseMove);
      document.addEventListener('mouseup', handleMouseUp);

      return () => {
        document.removeEventListener('mousemove', handleMouseMove);
        document.removeEventListener('mouseup', handleMouseUp);
      };
    }
  }, [isResizing, startX, startWidth]);

  return (
    <div
      className={`resizable-panel ${isResizing ? 'resizing' : ''} ${className}`}
      style={{ width: `${width}px` }}
      {...props}
    >
      {children}
      <div
        className="absolute top-0 right-0 w-1 h-full cursor-col-resize bg-transparent hover:bg-blue-400 transition-colors duration-200 z-10"
        onMouseDown={handleMouseDown}
      />
    </div>
  );
};

export default ResizablePanel; 