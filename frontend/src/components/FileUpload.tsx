import React, { useCallback, useState } from 'react';
import { Upload, File, X, CheckCircle } from 'lucide-react';

interface FileUploadProps {
  onFileSelect: (file: File) => void;
  isLoading?: boolean;
}

export const FileUpload: React.FC<FileUploadProps> = ({ onFileSelect, isLoading }) => {
  const [dragActive, setDragActive] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);

  const handleDrag = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  const handleDrop = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);

    const files = e.dataTransfer.files;
    if (files && files[0]) {
      const file = files[0];
      if (file.name.endsWith('.pcap') || file.type === 'application/octet-stream') {
        setSelectedFile(file);
        onFileSelect(file);
      } else {
        alert('Please select a valid .pcap file');
      }
    }
  };

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      const file = e.target.files[0];
      setSelectedFile(file);
      onFileSelect(file);
    }
  };

  const handleClear = () => {
    setSelectedFile(null);
  };

  return (
    <div className="w-full">
      {!selectedFile ? (
        <div
          onDragEnter={handleDrag}
          onDragLeave={handleDrag}
          onDragOver={handleDrag}
          onDrop={handleDrop}
          className={`border-2 border-dashed rounded-xl p-12 text-center transition-all cursor-pointer ${
            dragActive
              ? 'border-primary bg-primary bg-opacity-5'
              : 'border-gray-300 hover:border-primary hover:bg-gray-50'
          }`}
        >
          <div className="flex flex-col items-center gap-4">
            <div className={`w-16 h-16 rounded-full flex items-center justify-center ${
              dragActive ? 'bg-primary text-white' : 'bg-gray-100 text-gray-400'
            } transition-all`}>
              <Upload size={32} />
            </div>

            <div>
              <p className="text-xl font-bold text-gray-900">
                {dragActive ? 'Drop your PCAP file here' : 'Drag & drop your PCAP file'}
              </p>
              <p className="text-gray-500 mt-1">or click to browse</p>
            </div>

            <input
              type="file"
              accept=".pcap,.cap"
              onChange={handleChange}
              className="hidden"
              id="file-input"
              disabled={isLoading}
            />
            <label
              htmlFor="file-input"
              className={`btn-primary cursor-pointer ${isLoading ? 'opacity-50 cursor-not-allowed' : ''}`}
            >
              Browse Files
            </label>

            <p className="text-xs text-gray-500 mt-4">
              Supported format: .pcap (up to 500MB)
            </p>
          </div>
        </div>
      ) : (
        <div className="card border-2 border-green-200 bg-green-50">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <CheckCircle size={32} className="text-green-600" />
              <div>
                <p className="font-bold text-gray-900">File Selected</p>
                <p className="text-sm text-gray-600 flex items-center gap-2 mt-1">
                  <File size={16} />
                  {selectedFile.name}
                </p>
                <p className="text-xs text-gray-500 mt-1">
                  {(selectedFile.size / 1024 / 1024).toFixed(2)} MB
                </p>
              </div>
            </div>

            {!isLoading && (
              <button
                onClick={handleClear}
                className="p-2 hover:bg-green-200 rounded-lg transition text-gray-600"
              >
                <X size={20} />
              </button>
            )}
          </div>

          {isLoading && (
            <div className="mt-4 pt-4 border-t border-green-200">
              <div className="flex items-center gap-3">
                <div className="w-5 h-5 border-3 border-green-200 border-t-green-600 rounded-full animate-spin" />
                <span className="text-sm text-gray-700">Uploading and analyzing...</span>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
