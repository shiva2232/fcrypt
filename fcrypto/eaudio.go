package fcrypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"

	"github.com/faiface/beep"
	"github.com/faiface/beep/flac"
	"github.com/faiface/beep/mp3"
	"github.com/faiface/beep/vorbis"
	"github.com/faiface/beep/wav"
	"github.com/mjibson/go-dsp/fft"
	"gonum.org/v1/gonum/dsp/fourier"
)

/*
MFCC-locked file encryption/decryption using faiface/beep for multi-format decoding.

Pipeline:
- Decode audio (wav/mp3/flac/ogg/aiff) -> PCM
- Convert to mono & resample to 16 kHz
- MFCC: pre-emph -> framing (25ms,10ms hop) -> Hamming -> FFT(512) -> Mel(26) -> log -> DCT -> take 13
- Quantize MFCCs (round to 1 decimal by default; configurable with -quant)
- Hash (SHA-256) -> AES-256 key
- AES-GCM: output = nonce || ciphertext
*/

const (
	targetSampleRate = 16000
	frameLenMs       = 25
	hopLenMs         = 10
	preEmphasis      = 0.97
	nFFT             = 512
	numMelFilters    = 26
	numMFCC          = 13
	fMin             = 0.0
)
const quant = 1 //MFCC quantization factor (10=1dp, 100=2dp, 1=no quant)

func Eaudio(filePath, audioPath string, decrypt bool) {

	var mode = "encrypt"
	if decrypt {
		mode = "decrypt"
	}

	if filePath == "" || audioPath == "" {
		fmt.Println("Usage: fcrypt -decrypt<optional> -file <path> -from <audio> [-quant 10] -c<for checksum encryption>")
		os.Exit(1)
	}

	// 1) Decode audio, mono, resample to 16k
	samples, err := decodeAudioAny(audioPath)
	if err != nil {
		fail("decode audio:", err)
	}
	mono16k := toMono(samples.data, samples.format.NumChannels)
	mono16k = resampleLinear(mono16k, int(samples.format.SampleRate), targetSampleRate)

	// 2) Derive key from MFCCs (with quantization)
	key, err := deriveKeyFromMFCC(mono16k, targetSampleRate, quant)
	if err != nil {
		fail("derive key:", err)
	}

	// 3) Encrypt/Decrypt
	in, err := os.ReadFile(filePath)
	if err != nil {
		fail("read file:", err)
	}

	switch mode {
	case "encrypt":
		out, err := aesGCMEncrypt(in, key)
		if err != nil {
			fail("encrypt:", err)
		}
		outPath := filePath + ".enc"
		if err := os.WriteFile(outPath, out, 0644); err != nil {
			fail("write enc:", err)
		}
		fmt.Println("✅ Encrypted ->", outPath)
	case "decrypt":
		plain, err := aesGCMDecrypt(in, key)
		if err != nil {
			fail("decrypt (wrong audio/key?)", err)
		}
		outPath := strings.TrimSuffix(filePath, ".enc")
		if err := os.WriteFile(outPath, plain, 0644); err != nil {
			fail("write dec:", err)
		}
		fmt.Println("🎉 Decrypted ->", outPath)
	default:
		fail("bad -mode", errors.New("use encrypt|decrypt")) // not reachable location
	}
}

func fail(msg string, err error) {
	fmt.Println("Error:", msg, err)
	os.Exit(1)
}

/* -------------------- AUDIO DECODE (beep) -------------------- */

type decoded struct {
	data   []float64
	format beep.Format
}

func decodeAudioAny(path string) (decoded, error) {
	var (
		f   *os.File
		err error
	)
	f, err = os.Open(path)
	if err != nil {
		return decoded{}, err
	}
	ext := filepath.Ext(path)
	var (
		streamer beep.StreamSeekCloser
		format   beep.Format
	)
	switch ext {
	case ".wav":
		streamer, format, err = wav.Decode(f)
	case ".mp3":
		streamer, format, err = mp3.Decode(f)
	case ".flac":
		streamer, format, err = flac.Decode(f)
	case ".ogg":
		streamer, format, err = vorbis.Decode(f)
	default:
		err = fmt.Errorf("unsupported audio format: %s", ext)
	}
	if err != nil {
		f.Close()
		return decoded{}, err
	}
	defer func() {
		streamer.Close()
		f.Close()
	}()

	// read all samples
	buf := make([][2]float64, 2048)
	var frames [][2]float64
	for {
		n, ok := streamer.Stream(buf)
		if !ok {
			break
		}
		frames = append(frames, buf[:n]...)
	}

	// flatten into interleaved stereo (beep gives 2-ch always; if format.NumChannels==1, [1] is 0)
	out := make([]float64, len(frames)*2)
	for i, s := range frames {
		out[2*i] = s[0]
		out[2*i+1] = s[1]
	}

	return decoded{data: out, format: format}, nil
}

func toMono(interleaved []float64, channels int) []float64 {
	if channels <= 1 {
		// treat as mono in left channel positions
		m := make([]float64, (len(interleaved)+1)/2)
		for i := 0; i < len(m); i++ {
			m[i] = interleaved[2*i]
		}
		return m
	}
	N := len(interleaved) / channels
	mono := make([]float64, N)
	for i := 0; i < N; i++ {
		sum := 0.0
		for c := 0; c < channels; c++ {
			sum += interleaved[i*channels+c]
		}
		mono[i] = sum / float64(channels)
	}
	return mono
}

// simple linear resampler (good enough for MFCC keying)
func resampleLinear(x []float64, srFrom, srTo int) []float64 {
	if srFrom == srTo || len(x) == 0 {
		return x
	}
	ratio := float64(srTo) / float64(srFrom)
	Nout := int(math.Ceil(float64(len(x)) * ratio))
	y := make([]float64, Nout)
	for i := 0; i < Nout; i++ {
		srcPos := float64(i) / ratio
		j := int(math.Floor(srcPos))
		t := srcPos - float64(j)
		if j+1 < len(x) {
			y[i] = (1-t)*x[j] + t*x[j+1]
		} else {
			y[i] = x[len(x)-1]
		}
	}
	return y
}

/* -------------------- MFCC & KEY -------------------- */

func deriveKeyFromMFCC(samples []float64, sr, quant int) ([]byte, error) {
	mfccFrames, err := computeMFCCFrames(samples, sr, frameLenMs, hopLenMs, nFFT, numMelFilters, numMFCC, fMin, float64(sr)/2)
	if err != nil {
		return nil, err
	}
	if len(mfccFrames) == 0 {
		return nil, errors.New("no MFCC frames")
	}
	// mean over frames
	mean := make([]float64, numMFCC)
	for _, c := range mfccFrames {
		for i := 0; i < numMFCC; i++ {
			mean[i] += c[i]
		}
	}
	for i := range mean {
		mean[i] /= float64(len(mfccFrames))
	}

	// quantize (e.g., quant=10 => 1 decimal)
	if quant < 1 {
		quant = 1
	}
	h := sha256.New()
	for _, v := range mean {
		q := math.Round(v*float64(quant)) / float64(quant)
		// pack as float64 bytes for hashing (stable)
		b := make([]byte, 8)
		binary.LittleEndian.PutUint64(b, math.Float64bits(q))
		h.Write(b)
	}
	return h.Sum(nil), nil
}

func computeMFCCFrames(
	signal []float64,
	sr int,
	frameMs, hopMs, nfft, nMel, nCoeff int,
	fmin, fmax float64,
) ([][]float64, error) {
	// pre-emphasis
	s := preEmphasize(signal, preEmphasis)

	// framing
	frameLen := int(float64(sr) * float64(frameMs) / 1000.0)
	hopLen := int(float64(sr) * float64(hopMs) / 1000.0)
	frames := frameSignal(s, frameLen, hopLen)
	if len(frames) == 0 {
		return nil, errors.New("no frames")
	}

	// window
	win := hamming(frameLen)

	// mel filterbank
	numBins := nfft/2 + 1
	fb := melFilterBank(nMel, numBins, sr, fmin, fmax, nfft)

	// DCT (type-II) on filterbank energies
	dct := fourier.NewDCT(nMel)

	mfcc := make([][]float64, 0, len(frames))
	for _, frame := range frames {
		if len(frame) < frameLen {
			tmp := make([]float64, frameLen)
			copy(tmp, frame)
			frame = tmp
		} else if len(frame) > frameLen {
			frame = frame[:frameLen]
		}
		for i := 0; i < frameLen; i++ {
			frame[i] *= win[i]
		}

		// FFT -> power spectrum
		spec := powerSpectrum(frame, nfft)
		spec = spec[:numBins]

		// mel filterbank
		melE := applyFilterBank(spec, fb)

		// log
		for i := range melE {
			if melE[i] < 1e-12 {
				melE[i] = 1e-12
			}
			melE[i] = math.Log(melE[i])
		}

		// DCT -> MFCCs
		cep := make([]float64, nMel)
		dct.Transform(cep, melE)
		if nCoeff < len(cep) {
			cep = cep[:nCoeff]
		}
		mfcc = append(mfcc, cep)
	}
	return mfcc, nil
}

func preEmphasize(x []float64, alpha float64) []float64 {
	if len(x) == 0 {
		return x
	}
	y := make([]float64, len(x))
	y[0] = x[0]
	for i := 1; i < len(x); i++ {
		y[i] = x[i] - alpha*x[i-1]
	}
	return y
}

func frameSignal(x []float64, frameLen, hopLen int) [][]float64 {
	if frameLen <= 0 || hopLen <= 0 || len(x) < frameLen {
		return nil
	}
	nFrames := 1 + (len(x)-frameLen)/hopLen
	out := make([][]float64, 0, nFrames)
	for start := 0; start+frameLen <= len(x); start += hopLen {
		out = append(out, append([]float64(nil), x[start:start+frameLen]...))
	}
	return out
}

func hamming(n int) []float64 {
	w := make([]float64, n)
	N := float64(n - 1)
	for i := 0; i < n; i++ {
		w[i] = 0.54 - 0.46*math.Cos(2*math.Pi*float64(i)/N)
	}
	return w
}

func powerSpectrum(frame []float64, nfft int) []float64 {
	x := make([]float64, nfft)
	copy(x, frame)
	c := fft.FFTReal(x)
	ps := make([]float64, len(c))
	for i, v := range c {
		re := real(v)
		im := imag(v)
		ps[i] = (re*re + im*im) / float64(nfft)
	}
	return ps
}

func hz2mel(f float64) float64 {
	return 2595.0 * math.Log10(1.0+f/700.0)
}
func mel2hz(m float64) float64 {
	return 700.0 * (math.Pow(10.0, m/2595.0) - 1.0)
}

func melFilterBank(nMel, numBins, sr int, fmin, fmax float64, nfft int) [][]float64 {
	if fmax <= 0 || fmax > float64(sr)/2 {
		fmax = float64(sr) / 2
	}
	melMin := hz2mel(fmin)
	melMax := hz2mel(fmax)
	melPoints := make([]float64, nMel+2)
	for i := 0; i < nMel+2; i++ {
		melPoints[i] = melMin + (float64(i)/float64(nMel+1))*(melMax-melMin)
	}
	hzPoints := make([]float64, nMel+2)
	for i, m := range melPoints {
		hzPoints[i] = mel2hz(m)
	}
	bin := make([]int, nMel+2)
	for i, f := range hzPoints {
		bin[i] = int(math.Floor((float64(nfft) + 1.0) * f / float64(sr)))
		if bin[i] > numBins-1 {
			bin[i] = numBins - 1
		}
		if bin[i] < 0 {
			bin[i] = 0
		}
	}
	fb := make([][]float64, nMel)
	for m := 1; m <= nMel; m++ {
		fb[m-1] = make([]float64, numBins)
		for k := bin[m-1]; k < bin[m]; k++ {
			den := bin[m] - bin[m-1]
			if den > 0 && k >= 0 && k < numBins {
				fb[m-1][k] = float64(k-bin[m-1]) / float64(den)
			}
		}
		for k := bin[m]; k < bin[m+1]; k++ {
			den := bin[m+1] - bin[m]
			if den > 0 && k >= 0 && k < numBins {
				fb[m-1][k] = float64(bin[m+1]-k) / float64(den)
			}
		}
	}
	return fb
}

func applyFilterBank(power []float64, fb [][]float64) []float64 {
	out := make([]float64, len(fb))
	for i := range fb {
		var sum float64
		f := fb[i]
		lim := min(len(f), len(power))
		for k := 0; k < lim; k++ {
			sum += f[k] * power[k]
		}
		out[i] = sum
	}
	return out
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

/* -------------------- AES-GCM -------------------- */

func aesGCMEncrypt(plain, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:32])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ct := gcm.Seal(nil, nonce, plain, nil)
	var out bytes.Buffer
	out.Write(nonce)
	out.Write(ct)
	return out.Bytes(), nil
}

func aesGCMDecrypt(blob, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:32])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(blob) < ns {
		return nil, errors.New("ciphertext too short")
	}
	nonce := blob[:ns]
	ct := blob[ns:]
	return gcm.Open(nil, nonce, ct, nil)
}
