/// Hash-to-curve for `G1`, per RFC 9380.
///
/// # ⚠️ EXPERIMENTAL AND UNAUDITED — see ../README.md
///
/// Maps an arbitrary message to a `G1` point, which is what BLS signature
/// verification needs: a signature is checked against `H(message)`, so without
/// this a canister can decrypt a sealed secret but cannot verify that the vetKey
/// the subnet handed it is a genuine signature at all.
///
/// Three stages, following `ic_bls12_381::hash_to_curve::map_g1`:
///
///   1. `hash_to_field` — expand the message to two field elements;
///   2. **simplified SWU** onto an isogenous curve `E'`, then the 11-isogeny
///      back to `E`. The detour exists because `E` has `j`-invariant 0, where
///      SWU does not apply directly;
///   3. **cofactor clearing**, so the result lands in the prime-order subgroup
///      rather than merely on the curve.
///
/// The constants below were converted out of the reference's Montgomery form
/// rather than transcribed. Two independent checks on that conversion: it
/// reproduces the `G1` generator's x-coordinate, which is known separately, and
/// `SSWU_A`/`SSWU_B` come out equal to the `E'` coefficients RFC 9380 publishes
/// for this suite. `SSWU_XI` agreeing with the RFC's `Z = 11` is a third.

import Fp "Fp";
import G1 "G1";
import Hash "Hash";
import Array "mo:core/Array";
import Nat8 "mo:core/Nat8";
import Blob "mo:core/Blob";
import Text "mo:core/Text";

module {
  /// The curve parameter `x`, for cofactor clearing.
  let BLS_X : Nat = 0xd201_0000_0001_0000;

  /// `A` and `B` of the isogenous curve `E'`, on which SWU is defined.
  let SSWU_A : Fp.Fp = 12190336318893619529228877361869031420615612348429846051986726275283378313155663745811710833465465981901188123677;
  let SSWU_B : Fp.Fp = 2906670324641927570491258158026293881577086121416628140204402091718288198173574630967936031029026176254968826637280;

  /// The non-residue `Z`, which RFC 9380 fixes at 11 for this suite.
  let SSWU_XI : Fp.Fp = 11;

  /// `sqrt(-Z^3)`, used when `g(x0)` turns out not to be a square.
  let SQRT_M_XI_CUBED : Fp.Fp = 590728492726997966099618626120482682095437733689734941576187760067601492637096712773899690116980580577616657575925;

  /// Coefficients of the 11-isogeny from `E'` back to `E`.
  let ISO11_XNUM : [Fp.Fp] = [
    2712959285290305970661081772124144179193819192423276218370281158706191519995889425075952244140278856085036081760695,
    3564859427549639835253027846704205725951033235539816243131874237388832081954622352624080767121604606753339903542203,
    2051387046688339481714726479723076305756384619135044672831882917686431912682625619320120082313093891743187631791280,
    3612713941521031012780325893181011392520079402153354595775735142359240110423346445050803899623018402874731133626465,
    2247053637822768981792833880270996398470828564809439728372634811976089874056583714987807553397615562273407692740057,
    3415427104483187489859740871640064348492611444552862448295571438270821994900526625562705192993481400731539293415811,
    2067521456483432583860405634125513059912765526223015704616050604591207046392807563217109432457129564962571408764292,
    3650721292069012982822225637849018828271936405382082649291891245623305084633066170122780668657208923883092359301262,
    1239271775787030039269460763652455868148971086016832054354147730155061349388626624328773377658494412538595239256855,
    3479374185711034293956731583912244564891370843071137483962415222733470401948838363051960066766720884717833231600798,
    2492756312273161536685660027440158956721981129429869601638362407515627529461742974364729223659746272460004902959995,
    1058488477413994682556770863004536636444795456512795473806825292198091015005841418695586811009326456605062948114985,
  ];

  let ISO11_XDEN : [Fp.Fp] = [
    1353092447850172218905095041059784486169131709710991428415161466575141675351394082965234118340787683181925558786844,
    2822220997908397120956501031591772354860004534930174057793539372552395729721474912921980407622851861692773516917759,
    1717937747208385987946072944131378949849282930538642983149296304709633281382731764122371874602115081850953846504985,
    501624051089734157816582944025690868317536915684467868346388760435016044027032505306995281054569109955275640941784,
    3025903087998593826923738290305187197829899948335370692927241015584233559365859980023579293766193297662657497834014,
    2224140216975189437834161136818943039444741035168992629437640302964164227138031844090123490881551522278632040105125,
    1146414465848284837484508420047674663876992808692209238763293935905506532411661921697047880549716175045414621825594,
    3179090966864399634396993677377903383656908036827452986467581478509513058347781039562481806409014718357094150199902,
    1549317016540628014674302140786462938410429359529923207442151939696344988707002602944342203885692366490121021806145,
    1442797143427491432630626390066422021593505165588630398337491100088557278058060064930663878153124164818522816175370,
    1,
  ];

  let ISO11_YNUM : [Fp.Fp] = [
    1393399195776646641963150658816615410692049723305861307490980409834842911816308830479576739332720113414154429643571,
    2968610969752762946134106091152102846225411740689724909058016729455736597929366401532929068084731548131227395540630,
    122933100683284845219599644396874530871261396084070222155796123161881094323788483360414289333111221370374027338230,
    303251954782077855462083823228569901064301365507057490567314302006681283228886645653148231378803311079384246777035,
    1353972356724735644398279028378555627591260676383150667237975415318226973994509601413730187583692624416197017403099,
    3443977503653895028417260979421240655844034880950251104724609885224259484262346958661845148165419691583810082940400,
    718493410301850496156792713845282235942975872282052335612908458061560958159410402177452633054233549648465863759602,
    1466864076415884313141727877156167508644960317046160398342634861648153052436926062434809922037623519108138661903145,
    1536886493137106337339531461344158973554574987550750910027365237255347020572858445054025958480906372033954157667719,
    2171468288973248519912068884667133903101171670397991979582205855298465414047741472281361964966463442016062407908400,
    3915937073730221072189646057898966011292434045388986394373682715266664498392389619761133407846638689998746172899634,
    3802409194827407598156407709510350851173404795262202653149767739163117554648574333789388883640862266596657730112910,
    1707589313757812493102695021134258021969283151093981498394095062397393499601961942449581422761005023512037430861560,
    349697005987545415860583335313370109325490073856352967581197273584891698473628451945217286148025358795756956811571,
    885704436476567581377743161796735879083481447641210566405057346859953524538988296201011389016649354976986251207243,
    3370924952219000111210625390420697640496067348723987858345031683392215988129398381698161406651860675722373763741188,
  ];

  let ISO11_YDEN : [Fp.Fp] = [
    3396434800020507717552209507749485772788165484415495716688989613875369612529138640646200921379825018840894888371137,
    3907278185868397906991868466757978732688957419873771881240086730384895060595583602347317992689443299391009456758845,
    854914566454823955479427412036002165304466268547334760894270240966182605542146252771872707010378658178126128834546,
    3496628876382137961119423566187258795236027183112131017519536056628828830323846696121917502443333849318934945158166,
    1828256966233331991927609917644344011503610008134915752990581590799656305331275863706710232159635159092657073225757,
    1362317127649143894542621413133849052553333099883364300946623208643344298804722863920546222860227051989127113848748,
    3443845896188810583748698342858554856823966611538932245284665132724280883115455093457486044009395063504744802318172,
    3484671274283470572728732863557945897902920439975203610275006103818288159899345245633896492713412187296754791689945,
    3755735109429418587065437067067640634211015783636675372165599470771975919172394156249639331555277748466603540045130,
    3459661102222301807083870307127272890283709299202626530836335779816726101522661683404130556379097384249447658110805,
    742483168411032072323733249644347333168432665415341249073150659015707795549260947228694495111018381111866512337576,
    1662231279858095762833829698537304807741442669992646287950513237989158777254081548205552083108208170765474149568658,
    1668238650112823419388205992952852912407572045257706138925379268508860023191233729074751042562151098884528280913356,
    369162719928976119195087327055926326601627748362769544198813069133429557026740823593067700396825489145575282378487,
    2164195715141237148945939585099633032390257748382945597506236650132835917087090097395995817229686247227784224263055,
    1,
  ];

  /// The sign convention RFC 9380 calls `sgn0`: the low bit of the canonical
  /// representative. It is what makes the map deterministic about which of the
  /// two roots to take.
  func sgn0(a : Fp.Fp) : Bool = a % 2 == 1;

  /// Expands a message to `count` field elements, per RFC 9380 §5.2.
  ///
  /// `L = 64` bytes per element: enough excess over the 48-byte modulus that the
  /// reduction bias is negligible.
  public func hashToField(msg : [Nat8], dst : [Nat8], count : Nat) : [Fp.Fp] {
    let l = 64;
    let expanded = Hash.expandMessageXmd(msg, dst, count * l);
    Array.tabulate<Fp.Fp>(
      count,
      func i {
        var acc : Nat = 0;
        for (j in Array.keys(Array.tabulate<Nat>(l, func k = k))) {
          acc := acc * 256 + Nat8.toNat(expanded[i * l + j]);
        };
        acc % Fp.P;
      },
    );
  };

  /// Simplified SWU onto the isogenous curve (`map_g1.rs:544`).
  func mapToCurveSimpleSwu(u : Fp.Fp) : G1.Point {
    let usq = Fp.square(u);
    let xiUsq = Fp.mul(SSWU_XI, usq);
    let xisqU4 = Fp.square(xiUsq);
    let ndCommon = Fp.add(xisqU4, xiUsq);

    // When ndCommon vanishes the denominator would too, so the map substitutes
    // XI. Missing this branch gives a function that works on almost every input.
    let xDen = Fp.mul(
      SSWU_A,
      if (Fp.isZero(ndCommon)) { SSWU_XI } else { Fp.neg(ndCommon) },
    );
    let x0Num = Fp.mul(SSWU_B, Fp.add(Fp.one, ndCommon));

    let xDensq = Fp.square(xDen);
    let gxDen = Fp.mul(xDensq, xDen);
    let gx0Num = Fp.add(
      Fp.mul(Fp.add(Fp.square(x0Num), Fp.mul(SSWU_A, xDensq)), x0Num),
      Fp.mul(SSWU_B, gxDen),
    );

    // sqrt_candidate = u·v · (u·v^3)^((p-3)/4), the standard trick for computing
    // sqrt(u/v) with one exponentiation.
    let uv = Fp.mul(gx0Num, gxDen);
    let vsq = Fp.square(gxDen);
    let sqrtCandidate = Fp.mul(uv, Fp.pow(Fp.mul(uv, vsq), (Fp.P - 3 : Nat) / 4));

    let gx0Square = Fp.equal(Fp.mul(Fp.square(sqrtCandidate), gxDen), gx0Num);
    let x1Num = Fp.mul(x0Num, xiUsq);
    let y1 = Fp.mul(Fp.mul(Fp.mul(SQRT_M_XI_CUBED, usq), u), sqrtCandidate);

    let xNum = if (gx0Square) { x0Num } else { x1Num };
    var y = if (gx0Square) { sqrtCandidate } else { y1 };

    // The sign of y must track the sign of u, or the map is not injective on
    // the sign bit and signatures fail to verify half the time.
    if (sgn0(y) != sgn0(u)) { y := Fp.neg(y) };

    { x = xNum; y = Fp.mul(y, xDen); z = xDen };
  };

  /// Horner evaluation of one isogeny polynomial.
  func hornerEval(coeffs : [Fp.Fp], x : Fp.Fp, zpows : [Fp.Fp]) : Fp.Fp {
    let last : Nat = coeffs.size() - 1;
    var acc = coeffs[last];
    var j = 0;
    while (j < last) {
      acc := Fp.add(Fp.mul(acc, x), Fp.mul(zpows[j], coeffs[last - 1 - j : Nat]));
      j += 1;
    };
    acc;
  };

  /// The 11-isogeny from `E'` back to `E` (`map_g1.rs:583`).
  ///
  /// Takes and returns **homogeneous** projective coordinates — `(X:Y:Z)` meaning
  /// `(X/Z, Y/Z)` — which is what the SWU map produces and what the reference's
  /// `G1Projective` uses. This port's `G1.Point` is *Jacobian*, `(X/Z², Y/Z³)`,
  /// so the result has to be converted before it goes anywhere near `G1`. See
  /// `toJacobian`.
  func isoMap(p : G1.Point) : G1.Point {
    // zp[i] = z^(i+1), the powers the Horner evaluation needs to homogenise
    // each coefficient up to the degree of the polynomial.
    let zp = Array.tabulate<Fp.Fp>(
      15,
      func i {
        var acc = p.z;
        var k = 0;
        while (k < i) { acc := Fp.mul(acc, p.z); k += 1 };
        acc;
      },
    );

    let xNum = hornerEval(ISO11_XNUM, p.x, zp);
    var xDen = hornerEval(ISO11_XDEN, p.x, zp);
    var yNum = hornerEval(ISO11_YNUM, p.x, zp);
    var yDen = hornerEval(ISO11_YDEN, p.x, zp);

    // The x denominator is one degree lower than its numerator, hence the extra z.
    xDen := Fp.mul(xDen, p.z);
    yNum := Fp.mul(yNum, p.y);
    yDen := Fp.mul(yDen, p.z);

    {
      x = Fp.mul(xNum, yDen);
      y = Fp.mul(yNum, xDen);
      z = Fp.mul(xDen, yDen);
    };
  };

  /// Reinterprets a homogeneous projective point as a Jacobian one.
  ///
  /// `(X : Y : Z)` homogeneous is the affine point `(X/Z, Y/Z)`; the same point
  /// in Jacobian coordinates is `(X·Z : Y·Z² : Z)`, since `XZ/Z² = X/Z` and
  /// `YZ²/Z³ = Y/Z`. Three multiplications, no inversion.
  ///
  /// This conversion is the whole reason the first version of this file produced
  /// points that were not on the curve: the SWU map and the isogeny work in
  /// homogeneous coordinates, `G1` here works in Jacobian, and both are
  /// internally consistent — so nothing in the `G1` tests could have caught it.
  func toJacobian(p : G1.Point) : G1.Point {
    if (Fp.isZero(p.z)) { return G1.identity };
    return {
      x = Fp.mul(p.x, p.z);
      y = Fp.mul(p.y, Fp.square(p.z));
      z = p.z;
    };
  };

  /// Clears the cofactor (`g1.rs:800`).
  ///
  /// The reference writes this as `self - self.mul_by_x()`, which reads like a
  /// subtraction — but `mul_by_x` negates its result because the curve parameter
  /// `x` is negative (`g1.rs:791`). So the operation is `P + |x|·P`, and taking
  /// the expression at face value produces points that are on the curve but in
  /// the wrong subgroup.
  ///
  /// Without cofactor clearing, pairing-based verification would accept points
  /// it should reject.
  func clearCofactor(p : G1.Point) : G1.Point =
    G1.add(p, G1.mul(p, BLS_X));

  /// Hashes a message to a `G1` point.
  public func hashToCurve(msg : [Nat8], dst : [Nat8]) : G1.Affine {
    let u = hashToField(msg, dst, 2);
    let p0 = toJacobian(isoMap(mapToCurveSimpleSwu(u[0])));
    let p1 = toJacobian(isoMap(mapToCurveSimpleSwu(u[1])));
    G1.toAffine(clearCofactor(G1.add(p0, p1)));
  };

  /// Convenience wrapper taking the domain separator as text.
  public func hashToCurveText(msg : [Nat8], dst : Text) : G1.Affine =
    hashToCurve(msg, Blob.toArray(Text.encodeUtf8(dst)));
}
