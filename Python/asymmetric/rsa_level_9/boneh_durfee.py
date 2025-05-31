from __future__ import print_function
import time
from sage.all_cmdline import *   # import sage library
from Crypto.Util.number import long_to_bytes

############################################
# Config
##########################################

"""
Setting debug to true will display more informations
about the lattice, the bounds, the vectors...
"""
debug = False

"""
Setting strict to true will stop the algorithm (and
return (-1, -1)) if we don't have a correct
upperbound on the determinant. Note that this
doesn't necesseraly mean that no solutions
will be found since the theoretical upperbound is
usualy far away from actual results. That is why
you should probably use `strict = False`
"""
strict = False

"""
This is experimental, but has provided remarkable results
so far. It tries to reduce the lattice as much as it can
while keeping its efficiency. I see no reason not to use
this option, but if things don't work, you should try
disabling it
"""
helpful_only = True
dimension_min = Integer(7) # stop removing if lattice reaches that dimension

############################################
# Functions
##########################################

# display stats on helpful vectors
def helpful_vectors(BB, modulus):
    nothelpful = Integer(0)
    for ii in range(BB.dimensions()[Integer(0)]):
        if BB[ii,ii] >= modulus:
            nothelpful += Integer(1)

    print(nothelpful, "/", BB.dimensions()[Integer(0)], " vectors are not helpful")

# display matrix picture with 0 and X
def matrix_overview(BB, bound):
    for ii in range(BB.dimensions()[Integer(0)]):
        a = ('%02d ' % ii)
        for jj in range(BB.dimensions()[Integer(1)]):
            a += '0' if BB[ii,jj] == Integer(0) else 'X'
            if BB.dimensions()[Integer(0)] < Integer(60):
                a += ' '
        if BB[ii, ii] >= bound:
            a += '~'
        print(a)

# tries to remove unhelpful vectors
# we start at current = n-1 (last vector)
def remove_unhelpful(BB, monomials, bound, current):
    # end of our recursive function
    if current == -Integer(1) or BB.dimensions()[Integer(0)] <= dimension_min:
        return BB

    # we start by checking from the end
    for ii in range(current, -Integer(1), -Integer(1)):
        # if it is unhelpful:
        if BB[ii, ii] >= bound:
            affected_vectors = Integer(0)
            affected_vector_index = Integer(0)
            # let's check if it affects other vectors
            for jj in range(ii + Integer(1), BB.dimensions()[Integer(0)]):
                # if another vector is affected:
                # we increase the count
                if BB[jj, ii] != Integer(0):
                    affected_vectors += Integer(1)
                    affected_vector_index = jj

            # level:0
            # if no other vectors end up affected
            # we remove it
            if affected_vectors == Integer(0):
                print("* removing unhelpful vector", ii)
                BB = BB.delete_columns([ii])
                BB = BB.delete_rows([ii])
                monomials.pop(ii)
                BB = remove_unhelpful(BB, monomials, bound, ii-Integer(1))
                return BB

            # level:1
            # if just one was affected we check
            # if it is affecting someone else
            elif affected_vectors == Integer(1):
                affected_deeper = True
                for kk in range(affected_vector_index + Integer(1), BB.dimensions()[Integer(0)]):
                    # if it is affecting even one vector
                    # we give up on this one
                    if BB[kk, affected_vector_index] != Integer(0):
                        affected_deeper = False
                # remove both it if no other vector was affected and
                # this helpful vector is not helpful enough
                # compared to our unhelpful one
                if affected_deeper and abs(bound - BB[affected_vector_index, affected_vector_index]) < abs(bound - BB[ii, ii]):
                    print("* removing unhelpful vectors", ii, "and", affected_vector_index)
                    BB = BB.delete_columns([affected_vector_index, ii])
                    BB = BB.delete_rows([affected_vector_index, ii])
                    monomials.pop(affected_vector_index)
                    monomials.pop(ii)
                    BB = remove_unhelpful(BB, monomials, bound, ii-Integer(1))
                    return BB
    # nothing happened
    return BB

""" 
Returns:
* 0,0   if it fails
* -1,-1 if `strict=true`, and determinant doesn't bound
* x0,y0 the solutions of `pol`
"""
def boneh_durfee(pol, modulus, mm, tt, XX, YY):
    """
    Boneh and Durfee revisited by Herrmann and May
    
    finds a solution if:
    * d < N^delta
    * |x| < e^delta
    * |y| < e^0.5
    whenever delta < 1 - sqrt(2)/2 ~ 0.292
    """

    # substitution (Herrman and May)
    PR = PolynomialRing(ZZ, names=('u', 'x', 'y',)); (u, x, y,) = PR._first_ngens(3)
    Q = PR.quotient(x*y + Integer(1) - u) # u = xy + 1
    polZ = Q(pol).lift()

    UU = XX*YY + Integer(1)

    # x-shifts
    gg = []
    for kk in range(mm + Integer(1)):
        for ii in range(mm - kk + Integer(1)):
            xshift = x**ii * modulus**(mm - kk) * polZ(u, x, y)**kk
            gg.append(xshift)
    gg.sort()

    # x-shifts list of monomials
    monomials = []
    for polynomial in gg:
        for monomial in polynomial.monomials():
            if monomial not in monomials:
                monomials.append(monomial)
    monomials.sort()
    
    # y-shifts (selected by Herrman and May)
    for jj in range(Integer(1), tt + Integer(1)):
        for kk in range(floor(mm/tt) * jj, mm + Integer(1)):
            yshift = y**jj * polZ(u, x, y)**kk * modulus**(mm - kk)
            yshift = Q(yshift).lift()
            gg.append(yshift) # substitution
    
    # y-shifts list of monomials
    for jj in range(Integer(1), tt + Integer(1)):
        for kk in range(floor(mm/tt) * jj, mm + Integer(1)):
            monomials.append(u**kk * y**jj)

    # construct lattice B
    nn = len(monomials)
    BB = Matrix(ZZ, nn)
    for ii in range(nn):
        BB[ii, Integer(0)] = gg[ii](Integer(0), Integer(0), Integer(0))
        for jj in range(Integer(1), ii + Integer(1)):
            if monomials[jj] in gg[ii].monomials():
                BB[ii, jj] = gg[ii].monomial_coefficient(monomials[jj]) * monomials[jj](UU,XX,YY)

    # Prototype to reduce the lattice
    if helpful_only:
        # automatically remove
        BB = remove_unhelpful(BB, monomials, modulus**mm, nn-1)
        # reset dimension
        nn = BB.dimensions()[0]
        if nn == 0:
            print("failure")
            return 0,0

    # check if vectors are helpful
    if debug:
        helpful_vectors(BB, modulus**mm)
    
    # check if determinant is correctly bounded
    det = BB.det()
    bound = modulus**(mm*nn)
    if det >= bound:
        print("We do not have det < bound. Solutions might not be found.")
        print("Try with highers m and t.")
        if debug:
            diff = (log(det) - log(bound)) / log(2)
            print("size det(L) - size e^(m*n) = ", floor(diff))
        if strict:
            return -1, -1
    else:
        print("det(L) < e^(m*n) (good! If a solution exists < N^delta, it will be found)")

    # display the lattice basis
    if debug:
        matrix_overview(BB, modulus**mm)

    # LLL
    if debug:
        print("optimizing basis of the lattice via LLL, this can take a long time")

    BB = BB.LLL()

    if debug:
        print("LLL is done!")

    # transform vector i & j -> polynomials 1 & 2
    if debug:
        print("looking for independent vectors in the lattice")
    found_polynomials = False
    
    for pol1_idx in range(nn - 1):
        for pol2_idx in range(pol1_idx + 1, nn):
            # for i and j, create the two polynomials
            PR = PolynomialRing(ZZ, names=('w', 'z',)); (w, z,) = PR._first_ngens(2)
            pol1 = pol2 = 0
            for jj in range(nn):
                pol1 += monomials[jj](w*z+1,w,z) * BB[pol1_idx, jj] / monomials[jj](UU,XX,YY)
                pol2 += monomials[jj](w*z+1,w,z) * BB[pol2_idx, jj] / monomials[jj](UU,XX,YY)

            # resultant
            PR = PolynomialRing(ZZ, names=('q',)); (q,) = PR._first_ngens(1)
            rr = pol1.resultant(pol2)

            # are these good polynomials?
            if rr.is_zero() or rr.monomials() == [1]:
                continue
            else:
                print("found them, using vectors", pol1_idx, "and", pol2_idx)
                found_polynomials = True
                break
        if found_polynomials:
            break

    if not found_polynomials:
        print("no independant vectors could be found. This should very rarely happen...")
        return 0, 0 
    
    rr = rr(q, q)

    # solutions
    soly = rr.roots()

    if len(soly) == 0:
        print("Your prediction (delta) is too small")
        return 0, 0

    soly = soly[0][0]
    ss = pol1(q, soly)
    solx = ss.roots()[0][0]

    #
    return solx, soly

def example():
    ############################################
    # How To Use This Script
    ##########################################

    #
    # The problem to solve (edit the following values)
    #

    # the modulus
    N = Integer(138728501052719695830997827983870257879591108626209095010716818754108501959050430927220695106906763908822395818876460759364322997020222845247478635848425558793671347756842735011885094468024344931360037542098264527076663690119553302046205282212602106990248442514444587909723612295871002063257141634196430659767)
    # the public exponent
    e = Integer(60016485563460433620911462871489753027091796150597697863772440338904706321535832359517415034149374289955681381097544059467926029963755494161141305994584249448583991034102694954139120453335603006006970009433124857766494518747385902016093339683987307620366742481560543776055295663835860818720290861634213881385)

    # the hypothesis on the private exponent (the theoretical maximum is 0.292)
    delta = .26 # this means that d < N^delta

    #
    # Lattice (tweak those values)
    #

    # you should tweak this (after a first run), (e.g. increment it until a solution is found)
    m = 4 # size of the lattice (bigger the better/slower)

    # you need to be a lattice master to tweak these
    t = int((Integer(1)-Integer(2)*delta) * m)  # optimization from Herrmann and May
    X = Integer(2)*floor(N ** delta)  # this _might_ be too much
    Y = floor(N ** (Integer(1) / Integer(2)))    # correct if p, q are ~ same size

    #
    # Don't touch anything below
    #

    # Problem put in equation
    P = PolynomialRing(ZZ, names=('x', 'y',)); (x, y,) = P._first_ngens(2)
    A = int((N+1)/2)
    pol = 1 + x * (A + y)

    #
    # Find the solutions!
    #

    # Checking bounds
    if debug:
        print("=== checking values ===")
        print("* delta:", delta)
        print("* delta < 0.292", delta < 0.292)
        print("* size of e:", int(log(e)/log(2)))
        print("* size of N:", int(log(N)/log(2)))
        print("* m:", m, ", t:", t)

    # boneh_durfee
    if debug:
        print("=== running algorithm ===")
        start_time = time.time()

    solx, soly = boneh_durfee(pol, e, m, t, X, Y)

    # found a solution?
    if solx > 0:
        print("=== solution found ===")
        if False:
            print("x:", solx)
            print("y:", soly)

        d = int(pol(solx, soly) / e)
        print("private key found:", d)
        return d
    else:
        print("=== no solution was found ===")
        return Integer(0)

    if debug:
        print(("=== %s seconds ===" % (time.time() - start_time)))
    

if __name__ == "__main__":
    
    d = example()
    print("d =", d)

    # e = 60016485563460433620911462871489753027091796150597697863772440338904706321535832359517415034149374289955681381097544059467926029963755494161141305994584249448583991034102694954139120453335603006006970009433124857766494518747385902016093339683987307620366742481560543776055295663835860818720290861634213881385
    n = Integer(138728501052719695830997827983870257879591108626209095010716818754108501959050430927220695106906763908822395818876460759364322997020222845247478635848425558793671347756842735011885094468024344931360037542098264527076663690119553302046205282212602106990248442514444587909723612295871002063257141634196430659767)
    c = Integer(40254592670056897412607628206293101688805220813070436291135637864728213056255791064749974976546612178688674369066366922740751516162695397004586912385306024596939610039396946106249406597089442755317018963104229975283670995939592563335766562761230485826833361814955946571348001305529987233069227384314146133493)

    if (d > Integer(0)):
        decrypted_msg = pow(c, d, n)
        print("\nFLAG:", long_to_bytes(decrypted_msg).decode())
        print()