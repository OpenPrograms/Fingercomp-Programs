import numpy as np
from os import path
from math import floor
from struct import unpack
from pyaudio import PyAudio
from sys import argv,stdout,stderr,exit
if len(argv)==1:
	print(f"{argv[0]} <file> [-o outfile]",file=stderr)
	exit(-1)
f=open(argv[1],'rb')
def sin_wave(A, f, fs, phi, t):
    '''
    :params A:    振幅
    :params f:    信号频率
    :params fs:   采样频率
    :params phi:  相位
    :params t:    时间长度
    '''
    # 若时间序列长度为 t=1s, 
    # 采样频率 fs=1000 Hz, 则采样时间间隔 Ts=1/fs=0.001s
    # 对于时间序列采样点个数为 n=t/Ts=1/0.001=1000, 即有1000个点,每个点间隔为 Ts
    Ts = 1/fs
    n = t / Ts
    n = np.arange(n)
    y = A*np.sin(2*np.pi*f*n*Ts + phi*(np.pi/180))
    return y
rate, windowSize, step, channels = unpack(">dddd",f.read(32))
fileSize=path.getsize(argv[1])-32
length=(fileSize)/rate/channels/8/2*windowSize
fileSize=floor(min(fileSize,length * rate * channels * 8 * 2 / windowSize))
print(f"length: {fileSize}B/{length}s.")
delay=(step / rate)
chans=[unpack(">d",f.read(8))[0] for i in range(0,fileSize,8)]
buffer=np.array([])
maxAmplitude=np.max(chans[1::2])
f.close()

p=PyAudio()
stream = p.open(format=p.get_format_from_width(2),
                channels=1,
                rate=int(rate),
                output=True,
                frames_per_buffer=int(step))

try:
	out=argv.index("-o")
	import wave
	out=wave.open(argv[out+1],"wb")
	out.setnchannels(1)
	out.setsampwidth(2)
	out.setframerate(rate)
except:
	out=None

for sample in range(0,len(chans),int(channels)*2):
	buf=sin_wave(chans[sample+1]/maxAmplitude/channels,chans[sample],rate,0,delay)
	for i in range(2,int(channels)*2,2):
		buf+=sin_wave(chans[sample+1+i]/maxAmplitude/channels,chans[sample+i],rate,0,delay)
	data=(buf*32767).astype(np.int16).tostring()
	stream.write(data)
	if out:
		out.writeframes(data)
	stdout.write("\rPlaying: %0.2f/%0.2fs"%((sample/channels/2+1)*delay,length))
	'''
	buffer=np.concatenate((buffer,buf))
	if (sample/channels)%1000==0:
		#print(sample)
		play(buffer)
		buffer=np.array([])
		wait()'''
stream.close()
if out:
	out.close()