import { format } from 'date-fns';

type LogLevel = 'info' | 'warn' | 'error' | 'debug';

interface LogOptions {
  source?: string;
  data?: any;
}

function formatTime(): string {
  return format(new Date(), 'HH:mm:ss');
}

function formatMessage(level: LogLevel, message: string, options: LogOptions = {}): string {
  const time = formatTime();
  const source = options.source ? `[${options.source}]` : '';
  const data = options.data ? `\n${JSON.stringify(options.data, null, 2)}` : '';
  
  return `${time} ${source} ${level.toUpperCase()}: ${message}${data}`;
}

export function info(message: string, options?: LogOptions) {
  console.log(formatMessage('info', message, options));
}

export function warn(message: string, options?: LogOptions) {
  console.warn(formatMessage('warn', message, options));
}

export function error(message: string, error?: Error, options?: LogOptions) {
  const errorData = error ? {
    message: error.message,
    stack: error.stack,
    ...options?.data
  } : options?.data;
  
  console.error(formatMessage('error', message, { ...options, data: errorData }));
}

export function debug(message: string, options?: LogOptions) {
  if (process.env.NODE_ENV === 'development') {
    console.debug(formatMessage('debug', message, options));
  }
}

export const logger = {
  info,
  warn,
  error,
  debug
};
