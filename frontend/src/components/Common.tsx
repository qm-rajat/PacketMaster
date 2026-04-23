import React from 'react';
import { AlertCircle, CheckCircle, XCircle, Clock } from 'lucide-react';
import type { Analysis } from '../../types';

interface StatusBadgeProps {
  status: Analysis['status'];
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({ status }) => {
  const config = {
    pending: { bg: 'bg-gray-100', text: 'text-gray-800', icon: Clock },
    running: { bg: 'bg-blue-100', text: 'text-blue-800', icon: Clock },
    complete: { bg: 'bg-green-100', text: 'text-green-800', icon: CheckCircle },
    error: { bg: 'bg-red-100', text: 'text-red-800', icon: XCircle },
  };

  const { bg, text, icon: Icon } = config[status];

  return (
    <div className={`${bg} ${text} px-3 py-1 rounded-full flex items-center gap-2 w-fit text-sm font-medium`}>
      <Icon size={16} />
      <span>{status.charAt(0).toUpperCase() + status.slice(1)}</span>
    </div>
  );
};

interface SeverityBadgeProps {
  severity: 'high' | 'medium' | 'low';
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({ severity }) => {
  const config = {
    high: 'bg-red-100 text-red-800',
    medium: 'bg-yellow-100 text-yellow-800',
    low: 'bg-green-100 text-green-800',
  };

  return (
    <span className={`${config[severity]} px-3 py-1 rounded-full text-sm font-medium`}>
      {severity.toUpperCase()}
    </span>
  );
};

interface ThreatScoreBadgeProps {
  score: number;
}

export const ThreatScoreBadge: React.FC<ThreatScoreBadgeProps> = ({ score }) => {
  let color = 'text-green-600';
  let bg = 'bg-green-50';

  if (score >= 75) {
    color = 'text-red-600';
    bg = 'bg-red-50';
  } else if (score >= 50) {
    color = 'text-yellow-600';
    bg = 'bg-yellow-50';
  } else if (score >= 25) {
    color = 'text-orange-600';
    bg = 'bg-orange-50';
  }

  return (
    <div className={`${bg} ${color} px-4 py-2 rounded-lg font-bold text-lg`}>
      {score.toFixed(1)} / 100
    </div>
  );
};

export const LoadingSpinner: React.FC<{ size?: 'sm' | 'md' | 'lg' }> = ({ size = 'md' }) => {
  const sizeClass = {
    sm: 'w-6 h-6',
    md: 'w-8 h-8',
    lg: 'w-12 h-12',
  }[size];

  return (
    <div className={`${sizeClass} border-4 border-gray-200 border-t-primary rounded-full animate-spin`} />
  );
};

interface AlertBoxProps {
  type: 'success' | 'error' | 'warning' | 'info';
  message: string;
  onClose?: () => void;
}

export const AlertBox: React.FC<AlertBoxProps> = ({ type, message, onClose }) => {
  const config = {
    success: { bg: 'bg-green-50', border: 'border-green-200', icon: CheckCircle, iconColor: 'text-green-600' },
    error: { bg: 'bg-red-50', border: 'border-red-200', icon: XCircle, iconColor: 'text-red-600' },
    warning: { bg: 'bg-yellow-50', border: 'border-yellow-200', icon: AlertCircle, iconColor: 'text-yellow-600' },
    info: { bg: 'bg-blue-50', border: 'border-blue-200', icon: AlertCircle, iconColor: 'text-blue-600' },
  };

  const { bg, border, icon: Icon, iconColor } = config[type];

  return (
    <div className={`${bg} border ${border} rounded-lg p-4 flex items-start gap-3 animate-slide-in`}>
      <Icon className={`${iconColor} flex-shrink-0 mt-0.5`} size={20} />
      <p className="flex-1 text-sm">{message}</p>
      {onClose && (
        <button
          onClick={onClose}
          className="text-gray-400 hover:text-gray-600 flex-shrink-0"
        >
          ✕
        </button>
      )}
    </div>
  );
};

interface MetricCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon?: React.ReactNode;
  variant?: 'default' | 'success' | 'warning' | 'danger';
}

export const MetricCard: React.FC<MetricCardProps> = ({
  title,
  value,
  subtitle,
  icon,
  variant = 'default',
}) => {
  const variantClasses = {
    default: 'border-l-4 border-l-primary',
    success: 'border-l-4 border-l-success',
    warning: 'border-l-4 border-l-warning',
    danger: 'border-l-4 border-l-danger',
  };

  return (
    <div className={`card-hover ${variantClasses[variant]}`}>
      <div className="flex items-start justify-between">
        <div className="flex-1">
          <p className="text-sm text-gray-600 font-medium">{title}</p>
          <p className="text-2xl font-bold text-gray-900 mt-1">{value}</p>
          {subtitle && <p className="text-xs text-gray-500 mt-1">{subtitle}</p>}
        </div>
        {icon && <div className="text-gray-400 ml-4">{icon}</div>}
      </div>
    </div>
  );
};
