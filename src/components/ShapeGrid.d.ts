export interface ShapeGridProps {
  direction?: "right" | "left" | "up" | "down" | "diagonal";
  speed?: number;
  borderColor?: string;
  squareSize?: number;
  hoverFillColor?: string;
  shape?: "square" | "circle" | "triangle" | "hexagon";
  hoverTrailAmount?: number;
  className?: string;
}

declare const ShapeGrid: (props: ShapeGridProps) => React.ReactElement;
export default ShapeGrid;
