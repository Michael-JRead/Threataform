// src/icons.jsx — version-safe lucide-react shim
// Corporate npm mirrors may cache only older versions.  This file resolves
// every icon the app needs by trying current + historical names, so the app
// never crashes regardless of which 0.2xx–0.5xx+ version is installed.
import * as _L from 'lucide-react';

// Invisible placeholder rendered when a name is absent in the installed version.
const _Noop = ({ size = 16 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" />
);

// Try each name in order; return the first that exists, else _Noop.
const _g = (...names) => {
  for (const n of names) { if (_L[n]) return _L[n]; }
  return _Noop;
};

// ── Stable names (unchanged across all versions) ──────────────────────────
export const BookOpen        = _g('BookOpen');
export const Upload          = _g('Upload');
export const Brain           = _g('Brain');
export const Microscope      = _g('Microscope');
export const Building2       = _g('Building2');
export const Search          = _g('Search');
export const ShieldCheck     = _g('ShieldCheck');
export const ListChecks      = _g('ListChecks');
export const GitCompare      = _g('GitCompare');
export const ShieldAlert     = _g('ShieldAlert');
export const Zap             = _g('Zap');
export const Layers          = _g('Layers');
export const ChevronLeft     = _g('ChevronLeft');
export const ArrowRight      = _g('ArrowRight');
export const Trash2          = _g('Trash2', 'Trash');
export const FolderOpen      = _g('FolderOpen', 'Folder');
export const Shield          = _g('Shield');
export const Cloud           = _g('Cloud');
export const Lock            = _g('Lock');
export const ArrowLeftRight  = _g('ArrowLeftRight');
export const Globe           = _g('Globe');
export const Database        = _g('Database');
export const FileText        = _g('FileText', 'File');
export const ChevronDown     = _g('ChevronDown');
export const ChevronRight    = _g('ChevronRight');
export const Plus            = _g('Plus');
export const X               = _g('X');
export const Home            = _g('Home');
export const Settings        = _g('Settings');
export const Info            = _g('Info');
export const Eye             = _g('Eye');
export const EyeOff          = _g('EyeOff');
export const TrendingUp      = _g('TrendingUp');
export const Target          = _g('Target');
export const Activity        = _g('Activity');
export const ArrowUpRight    = _g('ArrowUpRight');
export const Square          = _g('Square');
export const PenLine         = _g('PenLine', 'Pen');
export const RotateCcw       = _g('RotateCcw');
export const Cpu             = _g('Cpu');
export const Server          = _g('Server');
export const Network         = _g('Network');
export const HardDrive       = _g('HardDrive');
export const Users           = _g('Users');
export const Plug            = _g('Plug');
export const Download        = _g('Download');
export const Package         = _g('Package');
export const MessageSquare   = _g('MessageSquare');
export const Send            = _g('Send');
export const ChevronUp       = _g('ChevronUp');
export const ClipboardList   = _g('ClipboardList', 'Clipboard');
export const RefreshCw       = _g('RefreshCw', 'RefreshCcw');

// ── Icons with known renames across versions ──────────────────────────────
// TriangleAlert: renamed from AlertTriangle in v0.381
export const TriangleAlert   = _g('TriangleAlert', 'AlertTriangle');

// AlertCircle: renamed to CircleAlert in v0.414 (old name kept as alias)
export const AlertCircle     = _g('AlertCircle', 'CircleAlert');

// CheckCircle: renamed to CircleCheck in v0.414
export const CheckCircle     = _g('CheckCircle', 'CircleCheck');

// CheckCircle2: renamed to CircleCheckBig in v0.414
export const CheckCircle2    = _g('CheckCircle2', 'CircleCheckBig', 'CircleCheck');

// XCircle: renamed to CircleX in v0.414
export const XCircle         = _g('XCircle', 'CircleX');

// CheckSquare: renamed to SquareCheck in v0.414
export const CheckSquare     = _g('CheckSquare', 'SquareCheck');

// BarChart / BarChart2: aliased to ChartBar / ChartBarBig in v0.414+
export const BarChart        = _g('BarChart', 'ChartBar');
export const BarChart2       = _g('BarChart2', 'ChartBarBig', 'BarChart');

// StopCircle: renamed to CircleStop in newer versions
export const StopCircle      = _g('StopCircle', 'CircleStop');

// Loader2: renamed to LoaderCircle in very new versions
export const Loader2         = _g('Loader2', 'LoaderCircle', 'Loader');

// AppWindow: added in v0.290; fallback to Window/Monitor
export const AppWindow       = _g('AppWindow', 'AppWindowMac', 'Monitor', 'Window');

// Sparkles: added in v0.314
export const Sparkles        = _g('Sparkles', 'Stars', 'Star');

// SquareStack: added later; fallback to Layers
export const SquareStack     = _g('SquareStack', 'Layers');

// DoorOpen: added later; fallback to LogOut
export const DoorOpen        = _g('DoorOpen', 'Door', 'LogOut');

// ScanLine: added later; fallback to Scan
export const ScanLine        = _g('ScanLine', 'ScanEye', 'Scan', 'Search');

// Code2: stable but fallback to Code
export const Code2           = _g('Code2', 'Code');

// BookMarked: stable but fallback to Bookmark
export const BookMarked      = _g('BookMarked', 'Bookmark');

// LayoutList: stable but fallback to List
export const LayoutList      = _g('LayoutList', 'List');

// KeyRound: added in v0.365; fallback to Key
export const KeyRound        = _g('KeyRound', 'Key');

// Bot: added in v0.362; fallback to Cpu
export const Bot             = _g('Bot', 'Robot', 'Cpu');

// ── Aliases (original import used "X as Y" syntax) ────────────────────────
export const MapIcon         = _g('Map');
export const ImageIcon       = _g('Image', 'ImageIcon');
export const LinkIcon        = _g('Link', 'LinkIcon', 'ExternalLink');

// ── KB Domain Icons (maps domain key → lucide icon component) ────────────────
// Kept here because it references icon components that are already exported above.
export const KB_DOMAIN_ICONS = {
  xsphere: Cloud, spinnaker: Settings, iam: KeyRound, jenkins: Server,
  dfd: MapIcon, wiz: ShieldAlert, attack: Zap, cwe: TriangleAlert,
  stride: Target, tfePave: Layers, userdocs: FileText,
};
