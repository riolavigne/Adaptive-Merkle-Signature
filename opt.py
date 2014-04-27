from math import log
from math import ceil
import copy

m = 256

hs = 0.00103516 #hashing things in ms
kg = 0.00446582 #key gen in ms

word = 32
block = 16

# Approx Winternitz setup time in ms
def wintSetup(l):
  t = ceil(m / (log (l, 2)))
  tp = ceil(log(t * l, l))
  n = t + tp
  return n*kg + (n*l + 1) * hs

# Approx Wint sign time in ms
def wintSign(l):
  t = ceil(m / (log (l, 2)))
  tp = ceil(log(t * l, l))
  n = t + tp
  return .5 * n * l * hs

# Size of Wint sig
def wintSigSize(l):
  t = ceil(m / (log (l, 2)))
  tp = ceil(log(t * l, l))
  n = t + tp
  return n * block

''' MERKLE '''
# Approx Merkle setup time in ms
def merkSetup(l, h):
  cap = 2**h
  return cap * kg + (cap - 1)*hs + cap * wintSetup(l)

# Approx Merkle signing time in seconds
def merkSign(l, h):
  return wintSign(l)

# Merkle Signature Size
def merkSigSize(l, h):
  return wintSigSize(l) + h * word + 2*word

''' ADAPTIVE '''
def adapSetup(l, h):
  sm = 0
  for i in range(len(l)):
    sm += merkSetup(l[i], h[i])
  for i in range(1, len(l)):
    sm += merkSign(l[i], h[i])
  return sm

def adapSign(l, h):
  cap = 1
  wintSum = 0
  avgOps = 1.0
  for i in range(len(l) - 1, -1, -1):
    cap = cap + cap * 2**h[i] # cap(1 + 2^h_i)
    wintSum += wintSetup(l[i])*cap
    avgOps += 1.0/cap
  wintAvg = wintSum/cap
  return merkSign(l[0], h[0])+ (wintAvg + hs)*avgOps

def adapSigSize(l, h):
  sm = 0
  for i in range(len(l)):
    sm += merkSigSize(l[i], h[i])
  return sm

def statelessSetup(l, h):
  return merkSetup(l[-1], h[-1])

def statelessSign(l, h):
  sm = 0
  for i in range(len(l) - 1):
    sm += merkSetup(l[i], h[i])
    sm += wintSign(l[i+1])
  return sm

def statelessSigSize(l, h):
  return adapSigSize(l, h)

MAX = 11
signLmt = 6 # ms -- this is RSA time
sigSizeLmt = 4 * 1024 # KB
setupLmt = 30*60*1000 # 30 minutes
levelsLmt = 7
minLevelsLmt = 5

# Minimize signing time
def optimize(cap):
  minSign = float("inf")
  min_h = []
  min_ell = []

  H = filter(lambda h: len(h) < levelsLmt and len(h) > minLevelsLmt, partitions(cap))
  for h in H:
    h.sort(reverse=True)
    print h
    L = len(h)
    ell = [2]*L
    while True:
      bigEll = []
      for l in ell:
        bigEll.append(2**l)
      if (adapSetup(bigEll, h) < setupLmt) and (adapSigSize(bigEll, h) < sigSizeLmt):
        if(adapSign(bigEll, h) < minSign):
          min_h = copy.deepcopy(h)
          min_ell = copy.deepcopy(bigEll)
      if (not addOne(ell)):
        break
  if not min_h:
    print "Failed to find any suitable results... Relax the bounds."
    return 0
  print "Capacity\tSigSize\tSetup Time\tSigning Time\tells\th's"
  print str(cap) +"\t" + str(adapSigSize(min_ell, min_h)) + "\t" + str(adapSetup(min_ell, min_h)) + "\t" + str(adapSign(min_ell, min_h)) + "\t" + str(min_ell) + "\t"+str(min_h)
  return 1

def addOne(ell):
  i = len(ell) - 1
  ell[-1] = ell[-1] + 1
  while(ell[i] > MAX):
    if i==0:
      return False
    ell[i-1] = ell[i-1] + 1
    for j in range(i, len(ell)):
      ell[j] = ell[i-1]
    i = i - 1
  return True

def partitions(n):
	# base case of recursion: zero is the sum of the empty list
	if n == 0:
		yield []
		return
	# modify partitions of n-1 to form partitions of n
	for p in partitions(n-1):
		yield [1] + p
		if p and (len(p) < 2 or p[1] > p[0]):
			yield [p[0] + 1] + p[1:]

optimize(64)

#h_s = [8, 8, 8, 8, 8, 10, 10, 10, 10, 12, 12, 12, 12]
#h_s.sort(reverse=True)
#ell_s = [512, 512, 512, 512, 512, 256, 128, 128, 64]
#ell_s.sort()
#print "Capacity\tSigSize\tSetup Time\tSigning Time\tells\th's"
#print "2^" + str(128) +"\t" + str(statelessSigSize(ell_s, h_s)) + "\t" + str(statelessSetup(ell_s, h_s)) + "\t" + str(statelessSign(ell_s, h_s)) + "\t" + str(ell_s) + "\t"+str(h_s)
#
#h_s = [8, 8, 8, 10, 10, 10, 10, 10, 12, 12, 12,12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12]
#h_s.sort(reverse=True)
#h_s.append(14)
#ell_s = [1024, 512, 512, 512, 512, 512, 512, 512, 256, 256, 256, 256, 128, 128, 128, 128, 128, 128, 128, 64, 64, 32, 16]
#ell_s.sort()
#print sum(h_s)
#if (len(h_s) is not len(ell_s)):
#  print "Lengths bad!"
#  print len(h_s)
#  print len(ell_s)
#print "Capacity\tSigSize\tSetup Time\tSigning Time\tells\th's"
#print "2^" + str(256) +"\t" + str(statelessSigSize(ell_s, h_s)) + "\t" + str(statelessSetup(ell_s, h_s)) + "\t" + str(statelessSign(ell_s, h_s)) + "\t" + str(ell_s) + "\t"+str(h_s)
#
#h_s = [8, 8, 8, 8, 8, 10, 10, 10, 10, 12, 12, 12, 12]+[8, 8, 8, 8, 8, 10, 10, 10, 10, 12, 12, 12, 12]
#h_s.sort(reverse=True)
#ell_s = [512, 512, 512, 512, 512, 256, 128, 128, 64]+[512, 512, 512, 512, 512, 256, 128, 128, 64]
#ell_s.sort()
#print "Capacity\tSigSize\tSetup Time\tSigning Time\tells\th's"
#print "2^" + str(sum(h_s)) +"\t" + str(statelessSigSize(ell_s, h_s)) + "\t" + str(statelessSetup(ell_s, h_s)) + "\t" + str(statelessSign(ell_s, h_s)) + "\t" + str(ell_s) + "\t"+str(h_s)


#ell = 100
#h = 5
#
#print "Cap\tSize\tSetup time\tSigning time"
#print str(1) + "\t"+str(wintSigSize(ell)) + "\t"+ str(wintSetup(ell)) + "\t" + str(wintSign(ell))
#
#print str(2**h) + "\t"+str(merkSigSize(ell, h)) + "\t"+ str(merkSetup(ell, h)) + "\t" + str(merkSign(ell, h))
#
#ells = [100, 1000, 1000]
#heights = [6, 5, 4]
#cap = 1
#for height in heights:
#  cap *= 2**height
#
#print str(cap) + "\t"+str(adapSigSize(ells, heights)) + "\t"+ str(adapSetup(ells, heights)) + "\t" + str(adapSign(ells, heights))

