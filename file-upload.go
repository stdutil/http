package http

import (
	"bytes"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// StoreUpload stores the form file upload into a temporary file returning the following values:
//
//   - TempFileName - temporary file name
//   - UploadFileName - original file name to upload
//   - UploadFileExt - original file name extension
//   - UploadFileSize - file size of the upload
//   - err - error information
func StoreUpload(r *http.Request, formName string) (TempFileName, UploadFileName, UploadFileExt string, UploadFileSize int64, err error) {
	var (
		ff       multipart.File
		fh       *multipart.FileHeader
		tempFile *os.File
	)

	if formName == "" {
		formName = "file"
	}

	ff, fh, err = r.FormFile(formName)
	if err != nil {
		return TempFileName, UploadFileName, UploadFileExt, UploadFileSize, err
	}
	defer ff.Close()

	if fh == nil {
		err = fmt.Errorf("no file was detected")
		return TempFileName, UploadFileName, UploadFileExt, UploadFileSize, err
	}

	fext := strings.ToLower(filepath.Ext(fh.Filename))
	tempFile, err = os.CreateTemp(os.TempDir(), "*"+fext)
	if err != nil {
		return TempFileName, UploadFileName, UploadFileExt, UploadFileSize, err
	}
	defer tempFile.Close()

	var (
		n  int
		nt int64
	)
	buff := make([]byte, 4096)
	for {
		n, err = ff.Read(buff)
		if err != nil && err != io.EOF {
			return TempFileName, UploadFileName, UploadFileExt, UploadFileSize, err
		}
		if n == 0 {
			break
		}
		_, err = tempFile.WriteAt(buff[0:n], nt)
		if err != nil {
			return TempFileName, UploadFileName, UploadFileExt, UploadFileSize, err
		}
		nt += int64(n)
	}
	if nt == 0 {
		err = fmt.Errorf("zero bytes read")
		return TempFileName, UploadFileName, UploadFileExt, UploadFileSize, err
	}

	// Prepare valid result
	UploadFileName = fh.Filename
	UploadFileExt = strings.ToLower(filepath.Ext(UploadFileName))
	UploadFileSize = fh.Size
	TempFileName = tempFile.Name()

	return TempFileName, UploadFileName, UploadFileExt, UploadFileSize, nil
}

// CreateUpload creates an uploadable data for http upload
//
// The function accepts the following parameters:
//   - fileName: the file name of the file to upload
//   - formName: the upload field name for the new upload request
//
// The function returns the following:
//   - *bytes.Buffer: The buffer data. To get bytes, it call the Bytes() function
//   - string: content type of the file
//   - error
func CreateUpload(fileName, formName string) (*bytes.Buffer, string, error) {
	var contentType string

	payload := new(bytes.Buffer)
	writer := multipart.NewWriter(payload)
	file, err := os.Open(fileName)
	if err != nil {
		return payload, contentType, err
	}
	defer file.Close()

	ioW, err := writer.CreateFormFile(formName, filepath.Base(fileName))
	if err != nil {
		return payload, contentType, err
	}
	_, err = io.Copy(ioW, file)
	if err != nil {
		return payload, contentType, err
	}
	err = writer.Close()
	if err != nil {
		return payload, contentType, err
	}
	contentType = writer.FormDataContentType()
	return payload, contentType, err
}

// CreateUploadFromRequest creates an uploadable data for http upload from an earlier upload.
//
// # This can be used to transfer uploaded file from the web to a file upload API that needs secure internal transfer
//
// The function accepts the following parameters:
//   - r: the request object from the web upload or form
//   - srcFormName: the upload field name from the original request
//   - dstFormName: the new upload field name for the new upload request
//
// The function returns the following:
//   - *bytes.Buffer: The buffer data. To get bytes, it call the Bytes() function
//   - string: content type of the file
//   - error
func CreateUploadFromRequest(r *http.Request, srcFormName, dstFormName string) (*bytes.Buffer, string, error) {
	var contentType string
	payload := new(bytes.Buffer)
	if srcFormName == "" {
		return payload, contentType, fmt.Errorf("source form name is not set")
	}

	file, hdr, err := r.FormFile(srcFormName)
	if err != nil {
		return payload, contentType, err
	}
	defer file.Close()

	writer := multipart.NewWriter(payload)

	if dstFormName == "" {
		dstFormName = srcFormName
	}

	ioW, err := writer.CreateFormFile(dstFormName, filepath.Base(hdr.Filename))
	if err != nil {
		return payload, contentType, err
	}
	_, err = io.Copy(ioW, file)
	if err != nil {
		return payload, contentType, err
	}
	err = writer.Close()
	if err != nil {
		return payload, contentType, err
	}
	contentType = writer.FormDataContentType()
	return payload, contentType, err
}
