with Interfaces; use Interfaces;
package RNG
  with SPARK_Mode => On,
       Abstract_State => (Entropy with External => Async_Writers)
is
   function Random_U64 return Unsigned_64
     with Global => Entropy,
          Volatile_Function;
end RNG;
