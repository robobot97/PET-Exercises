"""
just a bunch of random code lines, sort of a rough notepad of potential/used code
"""


#check if a point is infinity
if (x0 is None and y0 is None) or (x1 is None and y1 is None):
    raise Exception

#check if the points even exist on the Curve:
if (is_point_on_curve(a, b, p, x0, y0) == False) or (is_point_on_curve(a, b, p, x1, y1) == False):
    raise Exception

# check if points are equal, if so, raise Exception
if x0 == x1 and y0 == y1:
    raise Exception



lam = (y0.int_sub(y1)).int_mul(((x0.int_sub(x1)).pow(-1)).mod(p))
xr = (lam.pow(2).int_sub(x1)).int_sub(x0.mod(p))
yr = (lam.int_mul(x1.int_sub(xr))).int_sub(y1.mod(p))


lam = ((y0.int_sub(y1)).int_mul(((x0.int_sub(x1)).pow(-1)))).mod(p)
xr = ((lam.pow(2).int_sub(x1)).int_sub(x0)).mod(p)
yr = ((lam.int_mul(x1.int_sub(xr))).int_sub(y1)).mod(p)


"""
bx0 = Bn(x0)
bx1 = Bn(x1)
by0 = Bn(y0)
by1 = Bn(y1)
bp = Bn(p)

xr = (Bn(lam).pow(2) - Bn(x1) - (Bn(x0) % Bn(p))
yr = Bn(lam)*(Bn(x1)-Bn(xr)) - (Bn(y1) % Bn(p))

lam = Bn((by0.int_sub(by1)).int_mul((bx0.int_sub(bx1)).mod_inverse(bp)))
xr = Bn((lam.pow(2)).int_sub(bx1).int_sub((bx0.mod(bp))))
yr = Bn((lam.int_mul((bx1.int_sub(xr)))).int_sub(by1.mod(bp)))


lam = Bn((by0 - by1) * ((bx0 - bx1)^(-1))%bp)
xr = Bn(lam^2 - bx1 - bx0%bp)
yr = Bn(lam*(bx1 - xr) - by1%bp)
"""


lam = ((Bn(3).mod_mul((x.mod_mul(x,p)),p)).mod_add(a,p)).mod_mul(((Bn(2).mod_mul(y,p)).mod_inverse(m=p)),p)
xr = (lam.mod_mul(lam,p)).mod_sub((Bn(2).mod_mul(x,p)),p)
yr = (lam.mod_mul((x.mod_sub(xr,p)))).mod_sub(y,p)



lamls = Bn(3).mod_mul(x.mod_pow(2,p),p).mod_add(a,p)
lamrs = (Bn(2).mod_mul(y,p)).mod_inverse(p)
lam = lamls.mod_mul(lamrs,p)

xrls = lam.mod_pow(2,p)
xrrs = Bn(2).mod_mul(x,p)
xr = xrls.mod_sub(xrrs,p)

yrmid = x.mod_sub(xr,p)
yr = lam.mod_mul(yrmid,p).mod_sub(y,p)

Q = point_add(a,b,p,Q[0],Q[1],P[0],P[1])
