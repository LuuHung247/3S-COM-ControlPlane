declare module "react-cytoscapejs" {
  import type { ComponentType, CSSProperties } from "react";
  import type cytoscape from "cytoscape";

  export interface CytoscapeComponentProps {
    elements: cytoscape.ElementDefinition[] | unknown[];
    stylesheet?: cytoscape.Stylesheet[];
    layout?: cytoscape.LayoutOptions;
    style?: CSSProperties;
    cy?: (cy: cytoscape.Core) => void;
    wheelSensitivity?: number;
    minZoom?: number;
    maxZoom?: number;
    zoom?: number;
    pan?: cytoscape.Position;
    boxSelectionEnabled?: boolean;
    autoungrabify?: boolean;
    autounselectify?: boolean;
    panningEnabled?: boolean;
    userPanningEnabled?: boolean;
    zoomingEnabled?: boolean;
    userZoomingEnabled?: boolean;
    className?: string;
    id?: string;
  }

  const CytoscapeComponent: ComponentType<CytoscapeComponentProps>;
  export default CytoscapeComponent;
}

declare module "cytoscape-fcose" {
  const ext: unknown;
  export default ext;
}

declare module "cytoscape-dagre" {
  const ext: unknown;
  export default ext;
}
