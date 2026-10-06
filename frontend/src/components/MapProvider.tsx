import React, { useState } from 'react';
import { TileLayer } from 'react-leaflet';

export interface MapProviderConfig {
  name: string;
  url: string;
  attribution: string;
  maxZoom?: number;
  subdomains?: string[];
  requiresApiKey?: boolean;
}

export const MAP_PROVIDERS: Record<string, MapProviderConfig> = {
  openstreetmap: {
    name: 'OpenStreetMap (Default)',
    url: 'https://tile.openstreetmap.org/{z}/{x}/{y}.png',
    attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors',
    maxZoom: 19,
    requiresApiKey: false
  },
  carto_dark: {
    name: 'CARTO Dark Matter (Key Optional/Fallback)',
    url: 'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png',
    attribution: '&copy; <a href="https://carto.com/">CARTO</a> &copy; OpenStreetMap',
    maxZoom: 19,
    subdomains: ['a', 'b', 'c', 'd'],
    requiresApiKey: true
  }
};

interface MapTileLayerProps {
  preferredProvider?: string;
}

/**
 * Robust MapProvider Abstraction Component.
 * Config-driven: Defaults to OpenStreetMap without API keys.
 * If another provider is configured or fails to load, gracefully falls back to OpenStreetMap.
 */
export const MapTileProvider: React.FC<MapTileLayerProps> = ({ preferredProvider = 'openstreetmap' }) => {
  const [activeProviderKey, setActiveProviderKey] = useState<string>(preferredProvider);

  // If a provider requires an API key and none is provided, or encounters a tile error, fallback to OSM
  const handleTileError = () => {
    if (activeProviderKey !== 'openstreetmap') {
      console.warn(`[MapProvider] Provider ${activeProviderKey} failed or required API key. Falling back to OpenStreetMap.`);
      setActiveProviderKey('openstreetmap');
    }
  };

  const currentConfig = MAP_PROVIDERS[activeProviderKey] || MAP_PROVIDERS.openstreetmap;

  return (
    <TileLayer
      key={activeProviderKey}
      url={currentConfig.url}
      attribution={currentConfig.attribution}
      maxZoom={currentConfig.maxZoom || 19}
      subdomains={currentConfig.subdomains || 'abc'}
      eventHandlers={{
        tileerror: handleTileError
      }}
    />
  );
};
