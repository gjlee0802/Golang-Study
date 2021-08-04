package main
import (
	"fmt"
	"math"
)

/* Vertex structure */
type Vertexc struct{
	X, Y float64
}

/* method Abs return float64 math.Sqrt */
func (v Vertexc) Abs() float64{
	return math.Sqrt(v.X*v.X + v.Y*v.Y)
}

/* method Scale use pointer receiver */
func (v *Vertexc) Scale(f float64){
	v.X *= f
	v.Y *= f
}

func main(){
	myvertex := Vertexc{3, 4}
	myvertex.Scale(10)
	fmt.Println(myvertex.Abs())

}


